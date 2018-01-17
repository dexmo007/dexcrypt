package com.dexmohq.dexcrypt.hashing;

import com.dexmohq.dexcrypt.Blockchain;
import com.google.common.io.BaseEncoding;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

import static java.lang.Integer.rotateRight;

public class Sha256 extends ShaAlgorithm {

    protected int h0 = 0x6a09e667;
    protected int h1 = 0xbb67ae85;
    protected int h2 = 0x3c6ef372;
    protected int h3 = 0xa54ff53a;
    protected int h4 = 0x510e527f;
    protected int h5 = 0x9b05688c;
    protected int h6 = 0x1f83d9ab;
    protected int h7 = 0x5be0cd19;

    protected static final int[] k = {
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

    public Sha256() {
        super(64);
    }


    @Override
    protected void updateInternal(byte[] chunks) {
        for (int chunk = 0; chunk < chunks.length / 64; chunk++) {
            final int[] w = new int[64];
            for (int i = 0; i < 16; i++) {
                w[i] = ByteBuffer.allocate(Integer.BYTES).put(chunks, chunk * 64 + i * 4, 4).getInt(0);
            }
            for (int i = 16; i < 64; i++) {
                final int w15 = w[i - 15];
                int s0 = rotateRight(w15, 7) ^ rotateRight(w15, 18) ^ (w15 >>> 3);
                final int w2 = w[i - 2];
                int s1 = rotateRight(w2, 17) ^ rotateRight(w2, 19) ^ (w2 >>> 10);
                w[i] = w[i - 16] + s0 + w[i - 7] + s1;
            }
            int a = h0;
            int b = h1;
            int c = h2;
            int d = h3;
            int e = h4;
            int f = h5;
            int g = h6;
            int h = h7;
            for (int i = 0; i < 64; i++) {
                int s1 = rotateRight(e, 6) ^ rotateRight(e, 11) ^ rotateRight(e, 25);
                int ch = (e & f) ^ ((~e) & g);
                int temp1 = h + s1 + ch + k[i] + w[i];
                int s0 = rotateRight(a, 2) ^ rotateRight(a, 13) ^ rotateRight(a, 22);
                int maj = (a & b) ^ (a & c) ^ (b & c);
                int temp2 = s0 + maj;

                h = g;
                g = f;
                f = e;
                e = d + temp1;
                d = c;
                c = b;
                b = a;
                a = temp1 + temp2;
            }
            h0 += a;
            h1 += b;
            h2 += c;
            h3 += d;
            h4 += e;
            h5 += f;
            h6 += g;
            h7 += h;
        }
    }

    @Override
    protected byte[] digestInternal() {
        return ByteBuffer.allocate(Integer.BYTES * 8)
                .putInt(h0)
                .putInt(h1)
                .putInt(h2)
                .putInt(h3)
                .putInt(h4)
                .putInt(h5)
                .putInt(h6)
                .putInt(h7)
                .array();
    }

    public boolean test(byte[] input) {
        update(input);
        updateBuffer();
        return (h0 & 0xffff_0000) == 0;
    }

    @Override
    protected ShaAlgorithm clone() {
        return new Sha256();
    }

    public static void main(String[] args) throws NoSuchAlgorithmException {

        String data = "\\end{minted}\n" +
                "\\caption{Accept-Header einer GET-Anfrage im Browser}\n" +
                "\\end{listing}\n" +
                "Die verschiedenen Medientypen werden durch Kommata gelistet. Nach einem Medientyp können Parameter folgen. Für die Priorisierung ist der relative Qualitätsfaktor (\\enquote{q}) entscheidend. Dieser Wert muss zwischen 0 und 1 liegen, ein höherer Wert bedeutet höhere Priorität. Ohne Angabe eines expliziten Werts wird ein Standardwert von 1 verwendet, also die höchste Priorität. Zweites Kriterium für die Priorisierung ist die Reihenfolge der Auflistung. Im obigen Beispiel wird der Medientyp \\enquote{text/html} vor \\enquote{application/xhtml+xml} favorisiert.\n" +
                "Stehen diese beiden Medientypen nicht zur Verfügung wird XML vor anderen Formaten bevorzugt. Stellt eine Ressource beispielsweise XML- und JSON-Repräsentationen bereit, würde XML favorisiert werden.\n" +
                "\n" +
                "\n" +
                "Das letzte zentrale Prinzip von REST ist die zustandslose Kommunikation. Zustände werden nur auf dem Client durch eine Ressourcenrepräsentation gehalten oder am Server durch den persistenten Ressourcenstatus abgebildet. Transiente, clientspezifische Zustände dürfen nicht über die Dauer einer Anfrage gehalten werden. Das führt dazu, dass sich der Server nur während der Anfragenverarbeitung für Existenz des spezifischen Clients interessiert. Ein Trugschluss daraus ist allerdings, dass keine statusabhängigen Anfragen existieren. Der Client muss seinen Status mittels einer Repräsentation an den Server übermitteln. % todo bsp. token auth?? oder an dieser stelle abstrakt halten\n" +
                "Diese Zustandsunabhängigkeit ist ein Grundbaustein für die Skalierbarkeit der Applikation. Zwei aufeinanderfolgende Anfragen müssen nicht zwangsweise von der gleichen Serverinstanz bearbeitet werden, da keinem der beiden transiente Daten zur Verarbeitung fehlen können. Des Weiteren erfährt ein Client nicht zwangsweise davon, wenn zwischen zwei Anfragen ein Serverneustart oder Ähnliches stattgefunden hat.\n" +
                "Allgemein sinkt die Gefahr des Datenverlusts bei einem Absturz, wenn keine transienten Daten vorhanden sind.\\\\\n" +
                "Im Internet finden sich viele Diskussionen, ob die Verwendung von Cookies REST-konform ist. Diese Frage lässt sich nicht pauschal beantworten. Es hängt von der Art und Weise ab, wie Cookies verwendet werden, bzw. welche Informationen übermittelt werden. Eine Nutzung von Cookies ist das Speichern eines Schlüssels zu einer serverseitigen Session. Bei Bearbeitung der Anfrage wird der Schlüssel ausgewertet und Session-abhängig gehandelt. Anmeldesessions sind ein Beispiel für diese Daten. Dieses Vorgehen ist nicht REST-konform, da transiente Session-Daten auf dem Server gespeichert sind. Zustandsdaten können REST-konform auf dem Client gespeichert sein. Dazu müssen allerdings die vollständigen Daten enthalten sein. Eine Referenz auf transiente Daten ist nicht ausreichend. Ein typisches Beispiel dafür ist das Speichern der zuletzt besuchten Seite innerhalb einer Webseite. Ein Authentifizierungstoken könnte auch in einem Cookie übermittelt werden. Für Authentifizierung und Autorisierung sieht HTTP allerdings eine dedizierte Kopfzeile vor. \\cite{restantipatterns}\n" +
                "Eine verbreitete Technologie für Token-basierte Autorisierung ist OAuth 2.0 \\cite{oauth}.\n" +
                "- Server signiert Token\n" +
                "- enthält Anmeldedaten+expire+authorities/rollen\n" +
                "- client schickt mit jeder anfrage, server validiert signatur, damit client token daten nicht verändert hat, bspw. expiration date hochgesetzt, mehr rechte vergeben, verschlüsselt mithilfe eines Serverseitigen Secrets, efficiente Authentifiierung...\n" +
                "\n" +
                "- Ablaufdatum einer Session umsetzbar\n" +
                "- Invalidierung einer Session manuell nicht möglich, Token ist für Dauer der exp immer gültig\n" +
                "\n" +
                "% todo Quelle für POAuth?????? buch checken\n" +
                "\n" +
                "\n" +
                "\\subsection{Vergleich}\n" +
                "\n" +
                "\\cite{smartbear_soap_rest}\n" +
                "\n" +
                "Nicht direkt vergleichbar:\n" +
                "SOAP -> konkretes XML Übertragungsformat\n" +
                "REST -> abstrakter Architekturstil\n" +
                "\n" +
                "SOAP Web Services impl kann nicht RESTful sein, da nicht Standardmethoden zum Einsatz kommen, es muss immer POST verwendet werden, um SOAP Nachricht zu übertragen, GET unterstützt keinen Body\n" +
                "REST gibt Ressource vor, um verschiedene Aktionen zu trennen\n" +
                "\n" +
                "URI referenziert damit nicht die Ressource sondern, URI + SOAP Request Body\n" +
                "\n" +
                "REST verwendet unterschiedliche Ressourcenrepräsentationen, SOAP nur XML möglich\n" +
                "aber: RESTful heißt nicht, dass unterschiedliche Repräsentationen vorhanden sein müssen -> Architekturstil\n" +
                "\n" +
                "Anhängig von Architektur, ob diese Restful ist, SOAP trifft darüber keine Aussagen, spezifiziert lediglich das Nachrichtenformat\n" +
                "d.h. wenn man von den Standardmethoden absieht, kann keine Aussage über Restfulness getroffen werden, da impl des Server nicht bekannt ist. \n" +
                "\n" +
                "Vorteile REST:\n" +
                "- keine Tools nötig zur Interaktion\n" +
                "- effizienter: kleine Nachrichtenformate als XML unterstützt, selbst bei XML entfällt SOAP envelope: HTTP overhead bei beiden vorhanden; caching support für statische Ressourcen\n" +
                "- schneller: geringerer Serialisierungsaufwand, ggf. Client deserialisierung optimierte z.b. JavaScript und JSON -> geeigneter für Browser Clients; generell JSON Parsing schneller als XML Parsing\n" +
                "- weniger Bandbreite verwendet-> s. oben kleine Nachrichten\n" +
                "- REST ist an moderne Web Architektur angepasst, optimiert\n" +
                "\n" +
                "Vorteile SOAP:\n" +
                "- Sprachen-, Plattform und Transportunabhängigkeit: REST ist auch Sprachen und Plattformunabhängig, HTTP für Webanwendung ohnehin Pflicht -> kein Nachteil...\n" +
                "- Gut für verteilte Unternehmensumgebungen -> REST für Punkt-zu-Punkt Verbindung\n" +
                "- Standardisiert\n" +
                "- eingebaute Fehlerbehandlung: HTTP Error Codes?\n" +
                "- Automation, WSDL Client generation; aber Swagger oder andere API Definitionssprachen bieten ebenfalls Generierung von REST Clients an\n" +
                "\n" +
                "\\subsection{Asynchronität}\\label{basics_async}\n" +
                "Asynchrone Bewältigung von Aufgaben hat sowohl für den Server als auch den Client Relevanz. Ein Client sollte zum Beispiel eine Interaktionen mit einem Web Service nie blockierend gestalten, um den Nutzer weiterhin die Interaktion mit der Benutzeroberfläche zu ermöglichen. Dies hat sich als Standard für die Softwareentwicklung ergeben. Da im Rahmen dieser Arbeit die Server-seitige Architektur einer Webanwendung fokussiert wird, wird auf die Betrachtung von Asynchronität beim Entwurf von Clients an dieser Stelle nicht weiter eingegangen.\\\\\n" +
                "Es sind grundsätzlich zwei Bedeutungen von Asynchronität im Zusammenhang mit Webanwendungen zu unterscheiden. \\cite[pp. 173-176]{resthttp}\\\\\n" +
                "Einerseits meint man die asynchrone Kommunikation zwischen Client und Server. \n" +
                "Grundsätzlich ist HTTP ein synchrones Protokoll, jede Anfrage muss mit einer Antwort erwidert werden. Asynchrone Kommunikation über HTTP ist damit ausgeschlossen. Allerdings gibt es Ansätze, asynchrone Verarbeitung in diesem Kontext umzusetzen. Der Client schickt eine Anfrage an den Server, um die Verarbeitung in Gang zu setzen. Dieser erwidert mit HTTP Status Code ''202 ACCEPTED'' und signalisiert damit, dass die Anfrage gültig ist und die Verarbeitung begonnen hat. Nun gibt es verschiedene Möglichkeiten wie der Server dem Client das Ergebnis asynchron über HTTP bereitstellen kann.\\\\\n" +
                "Die erste dieser Möglichkeiten ist eine aktive Notifikation mittels HTTP Callback. Dazu muss der Client dem Server mit der Anfrage eine Callback-URL mitteilen. Nach der Bearbeitung schickt der Server die Antwort an die angegebene URI. Der entscheidende Nachteil dieser Umsetzung ist, dass der Client dabei selber ein Server sein muss. Er muss in der Lage sein, HTTP Anfragen entgegenzunehmen. Die Lösung ist also für reine Client-Anwendungen nicht geeignet.\\\\\n" +
                "Die zweite Möglichkeit bietet Polling. Dazu teilt der Server dem Client auf die initiale Anfrage eine Polling-URI mit. Dies könnte beispielsweise in der ''Location''-Kopfzeile der Antwort erfolgen. Nun kann der Client diese URI periodisch abfragen. Solange die Anfrage am Server noch in Verarbeitung ist, antwortet der Server mit einer Nachricht, dass die Ressource noch nicht verfügbar ist. Dies könnte beispielsweise über den HTTP Status Code ''404 NOT FOUND'' abgebildet sein. Steht die Antwort zur Verfügung, antwortet der Server mit ''200 OK'' und sendet das Ergebnis mit. Daraufhin kann diese temporäre Ressource am Server gelöscht werden. Daraus ergibt sich auch der erste Nachteil dieser Lösung. Der Server muss einen Prozess implementieren, der nicht abgefragte Ergebnisse nach einem bestimmten Zeitintervall entfernt. Ein weiterer Nachteil ist die erhöhte Netzwerklast durch die wiederholten Anfragen an den Server. Beide genannten Nachteile belasten Ressourcen der Client- sowie der Serverseite. Des Weiteren erhält der Client die Antwort nicht zum frühst möglichen Zeitpunkt, sondern erst nach der nächsten Abfrage. Der Vorteil gegenüber der Callback-Variante ist allerdings, dass diese Art der Asynchronität durch einen reinen Client, beispielsweise ein JavaScript-Client auf einer Webseite, implementiert werden kann. Denn der Client ist stets der Initiator der Verbindung. Um die wiederholten Abfragen zu vermeiden, kann ''Long Polling'' verwendet werden. Dabei wird die initiale Verbindung bis zum Zeitpunkt der Vollendung offengehalten. Damit werden allerdings für die Dauer der Verarbeitung auf beiden Seiten Ressourcen beansprucht.\\\\\n" +
                "Eine Erweiterung von Long Polling sind \\gls{sse}. Dabei handelt es sich um eine Technologie vom Server aktiv Nachrichten über HTTP an den Client zu schicken. Viele Browser unterstützen diese Technologie. Dies eignet sich optimal für Chat-Anwendungen, in denen die Nachrichten der Nutzer an die Clients weitergeleitet werden. Ein weiterer Anwendungsfall für SSE sind aktive Benachrichtigungen oder Push-Benachrichtigungen auf Webseiten. Ist man bereit das Protokoll zu wechseln, bieten WebSockets ebenfalls die Möglichkeit der asynchronen Kommunikation zwischen Client und Server. \\cite{resthttp}\n" +
                "\n" +
                "\n" +
                "Anderseits wird mit Asychronität oft die nicht-blockierende Bearbeitung von Anfragen am Server gemeint. Das heißt, die eigentliche Verarbeitung wird durch einen Thread als den der Anfrage abgeleistet. Normalerweise stellt ein Server ein Pool mit einer bestimmten Anzahl von Threads bereit. Bei ankommender Anfrage wird einer dieser Threads der Bearbeitung der Anfrage und Bereitstellung der Antwort zugeordnet. Für schnell abzuarbeitende Anfragen verursacht dieses Modell keine Probleme. Ein paar Hundert Threads können mehrere Tausend gleichzeitiger Nutzer bearbeiten. Verursachen die Anfragen allerdings längere Bearbeitungszeiten, wird der dedizierte Thread des Pool für die gesamte Bearbeitungsdauer blockiert. Fall der Server beispielsweise für die Bearbeitung einer Anfrage mit weiteren Web Services interagieren muss, wird ein Thread blockiert, obwohl dieses nicht weiter tut, als auf die Antwort des Web Service zu warten. Bei vielen gleichzeitigen Nutzer ergeben sich damit lange Antwortzeiten des Servers, da erst auf ein freier Thread und anschließend auf die eigentliche Antwort gewartet werden muss.\\\\\n" +
                "Seit JAX-RS 2.0 gibt es eine Möglichkeit diese Problematik zu umgeben, die \\mintinline{text}{AsyncResponse} API. Bei einer Anfrage wird der bekannte Thread-Pool verwendet, um diese entgegenzunehmen. Im Endpoint wird die intensive Bearbeitung, beispielsweise Warten auf eine Netzwerk-Ressource, an einen Hintergrund-Thread übergeben und der Thread der Anfrage kann wieder freigeben werden. Der Hintergrund-Thread hat Zugriff auf die \\mintinline{text}{AsyncResponse}-Instanz und kann die Antwort zurückgeben, sobald diese verfügbar ist. Der im Hintergrund arbeitende Thread kann auf beliebige Art und Weise erstellt werden. Es kann ein komplett neuer Thread mit \\mintinline{java}{new Thread()} erstellt werden. Es empfiehlt sich allerdings, einen \\mintinline{text}{ThreadPool} zu verwenden. Dies hat den Vorteil, dass bereits erstellte Thread wiederverwendet werden können. Weiterhin kann die maximal Anzahl gleichzeitiger Threads limitiert werden. Da die Erstellung eines neuen Threads einen gewissen Overhead mit sich bringt, beanspruchen eine hohe Anzahl von Threads eine große Menge an Ressourcen. Im Java EE Kontext gibt es außerdem die Möglichkeit dem Thread-Pool als Ressource zu definieren. Diese kann in einer entsprechenden Konfigurationsdatei angepasst werden, beispielsweise die maximale Anzahl an Threads oder die Zeit, in der ein inaktiver Thread am Leben gehalten wird. Mit der Annotation \\mintinline{java}{@Resource} kann der Service in ein Bean injiziert werden. \\cite{jaxrs}\n" +
                "\n" +
                "\n" +
                "Seit Java 8 hat Asynchronität in der Standard-Bibliothek einen größeren Fokus erhalten. Das Package \\mintinline{text}{java.util.concurrent} bietet Funktionalitäten in diesem Rahmen.\n" +
                "\n" +
                "\n" +
                "@Asynchronous: Markiert die annotierte Methode oder alle Geschäftsmethoden einer annotierten Klasse als asynchron. Der Rückgabewert bezogener Methoden muss entweder \\mintinline{java}{void} oder \\mintinline{java}{Future<R>} sein.\n" +
                "\n" +
                "\n" +
                "\n" +
                "\\section{E-Mail- und HTML-Generierung}\n" +
                "Trotz ständig wachsendem Anteil von reaktiven Webseiten, hat HTML-Generierung in der Webentwicklung immer noch Relevanz. Eine reaktive Webseite wird statisch vom Server bereitgestellt. Dynamische Informationen wie Nutzerprofil werden über die REST API des Servers abgerufen. Der Versand von E-Mail ist ein gutes Beispiel für die Notwendigkeiten von HTML-Generierung. Viele Systeme schicken automatisiert Benachrichtigung per E-Mail oder fordern den Nutzer auf die Registrierung zu bestätigen. Bei diesen E-Mail handelt es sich meistens nicht um statisch abgelegte E-Mail mit festem Inhalt, sondern die E-Mail wird basiert auf aktuellen Informationen zusammengestellt. Oft möchte ebenfalls die Möglichkeit haben, die E-Mails in verschiedenen Sprachen zu verschicken. Es gibt verschiedene Technologien, um in einem Java-Programm HTML-Dateien zu generieren. Im Folgenden werden drei Ansätze vorgestellt und verglichen. Im ersten Ansatz wird versucht, das Ziel ohne Verwendung von Frameworks zu erreichen. Man könnte die HTML-Datei mithilfe von String-Konkatenation zusammenbauen.\n" +
                "\\begin{listing}[H]\n" +
                "\\begin{minted}{java}\n" +
                "\"<h1>Welcome, \" + username + \"!</h1>\"\n" +
                "\\end{minted}\n" +
                "\\caption{HTML-Generierung durch String-Konkatenation}\n" +
                "\\end{listing}\n" +
                "Es lässt sich jedoch einfach erkennen, dass die Lösung für die Generierung größerer, komplexerer HTML-Dateien unpraktisch und umständlich ist.\\\\\n" +
                "Optimaler ist es, die HTML-Datei normal zu erstellen und dynamische Element mittels eines Platzhalters zu markieren. Diese werden zur Laufzeit durch die passenden Inhalte ersetzt. Für die Umsetzung dieser Methode existieren diverse Frameworks. Eines dieser ist Thymeleaf. Dabei handelt es sich um einen mächtigen Template Engine. Es ist ebenfalls der bevorzugte HTML-Generator im Spring MVC Framework. \n" +
                "\n" +
                "Ein komplett anderen Ansatz bietet das Framework J2HTML. Es bildet das HTML \\gls{dom} durch Java Objekte ab. Nach dem Builder-Pattern kann die HTML-Datei gebaut werden. Für komplexe Seiten, die mit CSS gestylt sind, wird das jedoch sehr schnell unübersichtlich.";

        final Blockchain bc = new Blockchain();

        long start = System.currentTimeMillis();
        int nonce = bc.mineSeqDex(data);
        long end = System.currentTimeMillis();
        System.out.println("dex   Found " + nonce + ": " + (end - start));

        start = System.currentTimeMillis();
        nonce = bc.mineSeqDexOpt(data);
        end = System.currentTimeMillis();
        System.out.println("dexop Found " + nonce + ": " + (end - start));


    }


}
