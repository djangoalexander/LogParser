  Acest script este gandit sa ruleze automat la startul sistemului de operare (task adaugat in Task Scheduler), inainte de login-ul userului. Este un parser de loguri (citeste logurile din Event Viewer) apoi le formateaza si prelucreaza informatiile pe care le scrie intr-un fisier .txt . Scriptul scrie un fisier txt cu evenimentele specifice care au avut loc cu o zi in urma (astazi scrie un fisier cu evenimentele de ieri). Scriptul verifica coduri din Winlog System, Winlog Security si Winlog Application. Acest script semnaleaza si evenimente care nu ar trebui sa apara in mod normal; pentru a intra in amanunte folositi filtrarile din EventViewer.
  Este ideal pentru cineva care doreste sa afle informatii concise cum ar fi:

- Cate logari/logout au avut loc si ce user le-a executat;
- Cate startari, restartari si shutdown-uri au avut log in ultima zi;
- Verifica si semnaleaza daca sunt erori generate de componente hardware;
- Verifica si semnaleaza daca sistemul a fost oprit neasteptat (Unexpected shutdown);
- Verifica si semnaleaza daca un serviciu a fost instalat în sistem, precum si multe alte evenimente (se monitorizeaza 32 de coduri).

  Scriptul poate fi rulat si direct modificand manual data in lastwritedate.txt; se poate pune orice data mai putin ziua curenta (scriptul nu va rula); orice data este valida atata timp cat sunt inregistrari in logul de 
windows pentru acea data.

Acest script este testat pe Windows 10 Pro si necesita instalat Python 3.13.0 (posibil sa functioneze ok si cu versiuni mai vechi).

ATENTIE !!! Inainte de rularea scriptului asigurati-va ca ati instalat corect pachetele (packages) pentru bibliotecile folosite in script (ex. pywin32 pentru win32evtlog).
