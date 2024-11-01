# Log Parser Ver. 1.6 (versiune scripta-bilă)
# Varianta cu winerror.HRESULT_CODE(record.EventID): Această funcție transformă codurile de eveniment negative în codurile lor pozitive corespunzătoare.
# Descriere: Citește winlog-ul windows dintre 2 date;
#            Tipărește cate înregistrări sunt in log pentru o lista de coduri de eveniment unice.
#            Avertizează daca anumite coduri vitale pentru securitate au fost găsite.
#            Afișează totalul login-urilor unui user predefinit si le afișează
#            Scrie rezultatele într-un fișier .txt
# Acest script a fost testat pe: Windows 10 Pro, Ver. 22H2

# Noutăți: A șasea versiune operatională, parametri linie de comandă (productive ready code).

import win32evtlog
from datetime import datetime
import winerror
import sys
import os
import ctypes
from ctypes import windll, create_unicode_buffer
import win32security
import argparse

# Blocul funcției MAIN unde se setează parametrii linie de comanda
def main():
    parser = argparse.ArgumentParser(description="Acesta este un parser de loguri pentru Windows 10.")
    parser.add_argument('-v', '--version', action='version', version='Versiunea 1.6')
    parser.add_argument('-t', '--tested', action='store_true', help='Arate pe ce SO a fost testat programul')
    argumente = parser.parse_args()
    _ = vars(argumente)  # Folosirea variabilei argumente pentru a evita warning-ul de variabilă nefolosită
    if argumente.tested:
        print("Acest script a fost testat pe: Windows 10 Pro, Ver. 22H2.")

    # Definirea unor variabile
    server = 'localhost'  # sau numele serverului
    log_type = ['Security', 'System', 'Application']
    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ

    # Blocul unde se setează variabilele cu Numele sistemului, userul si SID-ul userului logat

    def get_system_name():
        username = os.getlogin()
        sid = create_unicode_buffer(100)
        domain = create_unicode_buffer(100)
        sid_size = ctypes.c_ulong(100)
        domain_size = ctypes.c_ulong(100)
        name_use = ctypes.c_ulong()

        if windll.advapi32.LookupAccountNameW(None, username, sid, ctypes.byref(sid_size), domain, ctypes.byref(domain_size), ctypes.byref(name_use)):
            return domain.value
        else:
            raise ctypes.WinError()

    def get_username():
        return os.getlogin()

    def get_user_sid():
        username = get_username()
        sid = win32security.LookupAccountName(None, username)[0]
        sid_str = win32security.ConvertSidToStringSid(sid)
        return sid_str

    # Numele Sistemului
    system_name = get_system_name()
    # Utilizatorul logat
    user = get_username()
    # SID-ul utilizatorului
    user_sid = get_user_sid()

    # Blocul cu prelucrările Date/Time

    # Citim data ultimei scrieri a fișierului de loguri din lastwritedate.txt
    # Funcție pentru citirea datei din fișier
    def read_date_from_file(cale_fisier):
        try:
            if not os.path.exists(cale_fisier):
                raise FileNotFoundError("Fișierul nu există.")

            with open(cale_fisier, 'r') as file:
                data_fisier = file.read().strip()
                if not data_fisier:
                    raise ValueError("Fișierul este gol.")
                data_fisier = datetime.strptime(data_fisier, '%Y-%m-%d')
                return data_fisier
        except (ValueError, FileNotFoundError) as e:
            current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            with open('error.txt', 'a', encoding='utf-8') as error_file:
                error_file.write(f"[{current_time}] Eroare la citirea datei din fișier: {e}\n")
            sys.exit(1)

    # Citim data ultimei scrieri a fișierului de loguri din lastwritedate.txt
    file_date = read_date_from_file('lastwritedate.txt')

    # Calculăm data curentă
    current_date = datetime.now()
    # Implementam logica
    # Dacă data curentă > data din fișier
    if current_date.date() > file_date.date():
        start_date = file_date.replace(hour=0, minute=0, second=1)
        end_date = file_date.replace(hour=23, minute=59, second=59)

    # Dacă data curentă este egală cu data din fișier
    elif current_date.date() == file_date.date():
        sys.exit(0) # Scriptul nu se execută deoarece ziua nu s-a terminat.
    else:
        sys.exit(0) # Data curentă este mai veche decât data din fișier sau nu exista data în fișier

    # Setăm o variabilă "file_path" care sa conțină numele fișierului în care se vor scrie rezultatele precum si stringul conținut in end_date:
    file_path = end_date.strftime('%Y-%m-%d') + '_' + system_name + '_log.txt'

    # Listele cu Codurile Eveniment (EventCodes)
    # Dicționare cu toate codurile căutate pentru fiecare categorie
    winlog_codes_security = {
        4624: "Logon. Acest eveniment indică o autentificare reușită.",
        4625: "Acest eveniment indică o încercare de autentificare eșuată.",
        4634: "Logoff. (evenimentul indică faptul că o sesiune de utilizator a fost închisă; când faci Lock)",
        4647: "Logoff. (evenimentul este generat atunci când un utilizator inițiază în mod explicit procedura de deconectare; Logoff, Restart sau Shutdown)",
        4672: "Acest eveniment indică faptul că un cont a primit drepturi speciale, cum ar fi privilegii administrative.",
        4688: "Creare de nou proces. (oferă detalii despre procesul părinte și cel copil, precum și despre utilizatorul care a inițiat procesul)",
        4697: "ServiceInstall. (Acest eveniment indică faptul că un serviciu a fost instalat în sistem)",
        4698: "Indică faptul că un task programat a fost creat.",
        4699: "Indică ca un scheduled task a fost șters.",
        4700: "Indică faptul că un task programat a fost modificat.",
        4701: "Indică faptul că un task programat a fost dezactivat.",
        4702: "Indică faptul că un task programat a fost activat.",
        4720: "Acest eveniment indică crearea unui nou cont de utilizator.",
        4726: "Acest eveniment indică ștergerea unui cont de utilizator.",
        4732: "Acest eveniment indică adăugarea unui utilizator într-un grup de securitate.",
        4767: "Acest eveniment indică deblocarea unui cont de utilizator.",
        5140: "Acest eveniment indică accesul la un fișier partajat."
    }

    winlog_codes_aplication = {
        106: "Acest eveniment este generat atunci când un utilizator se conectează la un sistem.",
        201: "Acest eveniment este generat atunci când un driver de dispozitiv este încărcat.",
        1100: "Event-viewer service shutdown (Probabil shutdown sau restart la sistem).",
        1102: "Logurile au fost șterse."
    }

    winlog_codes_system = {
        4: "Memory: A hardware failure occurred.",
        7: "Disk: The requested operation could not be performed on specified drive.",
        9: "Disk: The driver detected a controller error on specified drive.",
        41: "Kernel-Power: The system has rebooted without cleanly shutting down first.",
        51: "An error was detected on device specified device during a paging operation.",
        1074: "Acest eveniment este generat la Shutdown / Restart",
        6005: "Serviciul Event Log a fost pornit.",
        6006: "Serviciul Event Log a fost oprit.",
        6008: "Oprire neașteptată a sistemului. (Unexpected shutdown)",
        6013: "Timpul de funcționare al sistemului. (System uptime)",
        7001: "System Started - Logon"
    }

    # Lista cu codurile eveniment importante d.p.d.v. al Hacking-ului
    important_codes = [4, 7, 9, 41, 51, 1102, 4625, 4672, 4697, 4720, 4726, 4732, 6008]

    # Funcție: Prelucrare loguri
    def parse_log(logtype, winlogcode):
        hand = win32evtlog.OpenEventLog(server, logtype)
        events = []
        try:
            while records := win32evtlog.ReadEventLog(hand, flags, 0):
                events.extend(records)
        except Exception as e:
            print(f"Eroare la citirea logului: {e}")
        finally:
            win32evtlog.CloseEventLog(hand)

        return [event for event in events if winerror.HRESULT_CODE(event.EventID) in winlogcode and start_date <= event.TimeGenerated <= end_date]

    # Variabilele conțin evenimente_filtrate pentru fiecare tip de log si key de securitate
    evenimente_security = parse_log(log_type[0], winlog_codes_security)
    evenimente_system = parse_log(log_type[1], winlog_codes_system)
    evenimente_aplication = parse_log(log_type[2], winlog_codes_aplication)

    # Funcție: căutarea numărului de apariții pentru fiecare key din dicționar
    def numar_aparitii_key(winlogcod, tip_evenimente):
        return '\n'.join(
            f"Codul {key} - ({winlogcod[key]}) - are {sum(1 for eveniment in tip_evenimente if winerror.HRESULT_CODE(eveniment.EventID) == key)} înregistrări în log."
            for key in winlogcod if any(winerror.HRESULT_CODE(eveniment.EventID) == key for eveniment in tip_evenimente)
        )

    nr_key_security = numar_aparitii_key(winlog_codes_security, evenimente_security)
    nr_key_system = numar_aparitii_key(winlog_codes_system, evenimente_system)
    nr_key_application = numar_aparitii_key(winlog_codes_aplication, evenimente_aplication)

    # Funcție: identificarea codurilor din important_code in lista evenimente_system
    def check_codes(coduri_importante, evenimente_sistem):
        found_codes = {winerror.HRESULT_CODE(eveniment.EventID) for eveniment in evenimente_sistem if winerror.HRESULT_CODE(eveniment.EventID) in coduri_importante}
        return ', '.join(map(str, found_codes)) if found_codes else None

    # Apelare funcție identificarea codurilor importante
    identif_important_security_codes = check_codes(important_codes, evenimente_security) # pentru Evenimentele de Securitate
    identif_important_system_codes = check_codes(important_codes, evenimente_system) # pentru Evenimentele de Sistem
    identif_important_aplication_codes = check_codes(important_codes, evenimente_aplication) # pentru Evenimentele din Aplicații

    # Funcție pentru afișarea evenimentelor

    def event_selector(evenimente_sistem, nr_event, string_pos, strings):
        # Secțiunea Login-uri din Security-code
        return [eveniment for eveniment in evenimente_sistem if
                           winerror.HRESULT_CODE(eveniment.EventID)  == nr_event and eveniment.StringInserts[string_pos] in strings]

    # Apelarea funcției event_selector rezultând type_event's
    login_user = event_selector(evenimente_security, 4624, 5, [user])
    logoff_user = event_selector(evenimente_security, 4647, 1, [user])
    power_on = event_selector(evenimente_system, 7001, 0, ['1'])
    power_off = event_selector(evenimente_system, 1074, 6, [f'{system_name}\\{user}'])

    # Funcția afișează eventurile in funcție de event_selector
    def universal_function(type_event, ev_string_number):
        # Elimină duplicatele (înregistrări identice apărute la o secundă consecutiv)
        unique_type_event = []
        seen_times = set()
        for event in type_event:
            event_time = event.TimeGenerated.strftime('%Y-%m-%d %H:%M:%S')
            if event_time not in seen_times:
                unique_type_event.append(event)
                seen_times.add(event_time)
        result = ""
        for eveniment in unique_type_event:
            if unique_type_event == power_off:
                result += f"Event ID: 1074, Time: {eveniment.TimeGenerated}, Task Category: {eveniment.EventCategory}, User: {eveniment.StringInserts[ev_string_number]}, Tip: {eveniment.StringInserts[4]}\n"
            else:
                result += f"Event ID: {eveniment.EventID}, Time: {eveniment.TimeGenerated}, Task Category: {eveniment.EventCategory}, User: {eveniment.StringInserts[ev_string_number]}\n"
        return result, unique_type_event

    # Apelăm funcția și salvăm rezultatele pentru login_user
    rezultat, evenimente_unice = universal_function(login_user, 5)
    # Scriem numărul total de logon-uri unice
    print_nr_logon = len(evenimente_unice)
    # Scriem Logon-urile
    print_logon = rezultat

    # Apelăm funcția și salvăm rezultatele pentru logoff_user
    rezultat, evenimente_unice = universal_function(logoff_user, 1)
    # Scriem numărul total de logoff-uri unice
    print_nr_logoff = len(evenimente_unice)
    # Scriem Logoff-urile
    print_logoff = rezultat

    # Apelăm funcția și salvăm rezultatele pentru Power ON
    rezultat, evenimente_unice = universal_function(power_on, 1)
    # Scriem numărul total de Power ON-uri
    print_nr_pwron = len(evenimente_unice)
    # Scriem Power ON-urile
    print_pwron = rezultat

    # Apelăm funcția și salvăm rezultatele pentru Power OFF
    rezultat, evenimente_unice = universal_function(power_off, 6)
    # Scriem numărul total de Power OFF-uri
    print_nr_pwroff = len(evenimente_unice)
    # Scriem Power OFF-urile
    print_pwroff = rezultat

    # Salvăm rezultatele într-un fișier nou (golind fișierul dacă există deja)
    with open(file_path, 'w', encoding='utf-8') as output_file:
        output_file.write(f"Loguri din perioada {start_date.strftime('%Y-%m-%d %H:%M:%S')} până la {end_date.strftime('%Y-%m-%d %H:%M:%S')}\n")
        output_file.write(f"Logul a fost scris ultima data in fișier la data/ora: {current_date.strftime('%Y-%m-%d %H:%M:%S')}\n")
        output_file.write(f"Userul logat in momentul rulării scriptului este: {user} cu SID-ul: {user_sid}\n")
        output_file.write("\n")
        output_file.write(nr_key_security + '\n')
        output_file.write(nr_key_system + '\n')
        output_file.write(nr_key_application + '\n')

        if identif_important_security_codes:
            output_file.write(f"ATENTIE!!! Următoarele coduri critice din Security au fost găsite: {identif_important_security_codes}\n\n")
        if identif_important_system_codes:
            output_file.write(f"ATENTIE!!! Următoarele coduri critice din System au fost găsite: {identif_important_system_codes}\n\n")
        if identif_important_aplication_codes:
            output_file.write(f"ATENTIE!!! Următoarele coduri critice din Aplicații au fost găsite: {identif_important_aplication_codes}\n\n")

        output_file.write(f"Numărul total de logon-uri unice pentru utilizatorul '{user}': {print_nr_logon}\n")
        output_file.write(print_logon)
        output_file.write(f"\nNumărul total de logoff-uri unice pentru utilizatorul '{user}': {print_nr_logoff}\n")
        output_file.write(print_logoff)
        output_file.write(f"\nNumărul total de Power ON-uri: {print_nr_pwron}\n")
        output_file.write(print_pwron)
        output_file.write(f"\nNumărul total de Power OFF-uri: {print_nr_pwroff}\n")
        output_file.write(print_pwroff)
    with open('lastwritedate.txt', 'w', encoding='utf-8') as lastdate_file:
        lastdate_file.write(current_date.strftime("%Y-%m-%d"))

if __name__ == "__main__":
    main()
