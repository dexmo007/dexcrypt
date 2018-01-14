package com.dexmohq.dexcrypt;

import com.google.common.hash.Hashing;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class Blockchain {

    private long mineSeq(String data) {
        for (long i = -1; i < Long.MAX_VALUE; i++) {
            final long nonce = i + 1;
            final String hash = Hashing.sha256().hashString(Long.toString(nonce) + data, StandardCharsets.UTF_8).toString();
            if (hash.startsWith("0000")) {
                return nonce;
            }
        }
        throw new IllegalStateException("No nonce found");
    }

    private long mineParallel(String data, int parallelism) {
        final ExecutorService es = Executors.newFixedThreadPool(parallelism);
        final ArrayList<Callable<Long>> tasks = new ArrayList<>();
        for (int i = 0; i < parallelism; i++) {
            final long starting = i;
            tasks.add(() -> {
                long nonce = starting;
                while (nonce != -1) {
                    final String hash = Hashing.sha256().hashString(Long.toString(nonce) + data, StandardCharsets.UTF_8).toString();
                    if (hash.startsWith("0000")) {
                        return nonce;
                    }
                    nonce += parallelism;
                }
                throw new IllegalStateException();
            });
        }
        try {
            final Long nonce = es.invokeAny(tasks);
            es.shutdown();
            return nonce;
        } catch (InterruptedException | ExecutionException e) {
            throw new RuntimeException(e);
        }
    }

    public static void main(String[] args) {
        final Blockchain bc = new Blockchain();
        String data = "Eine Information im Web wird als Ressource abstrahiert. Dies kann ein einzelner Eintrag oder eine Ansammlung mehrerer Einträge sein. Ebenfalls ein abwesender Eintrag ist eine Information. Es liegt die Vermutung nahe, dass die Begriffe Ressource und Entität synonym definiert sind. Für die REST-Sicht ist Existenz der konkreten Entität erstmal irrelevant. Eine Ressource ist lediglich eine offengelegte Information. Diese Informationen kann aus mehreren Entitäten zusammengesetzt sein. Es dürfen Entitäten existieren, die nicht als Ressource exponiert sind und nur im Hintergrund relevant sind. Da aus REST-Sicht die konkrete Implementierung ohne Relevanz ist, muss Entität separat definiert sein.\n" +
                "Es ist ebenfalls möglich, dass mehrere Ressourcen zu einem Zeitpunkt auf die selbe Entität verweise. Durch die verschiedenen Ressourcen erhält die Entität allerdings unterschiedliche Bedeutungen. Man stelle sich die Ressourcen ''bester Film des Jahrzehnts'' und ''bester deutsch-sprachiger Film 2017'' vor. Zu einem bestimmten Zeitpunkt ist es möglich, dass beide auf den gleichen Film verweisen, also die selbe Entität. Die Bedeutung des Werts ist allerdings verschieden. Beide Ressource sind stets unabhängig voneinander und müssen eindeutig referenziert werden können. Daraus ergibt sich das erste Grundprinzip von REST, die eindeutige Identifikation von Ressourcen.\\\\\n" +
                "Das nächste Grundprinzip von REST ist Hypermedia. Es wurde bereits angesprochen, dass eine Ressource aus mehreren Informationen zusammengesetzt sein kann. Nun gibt es zwei Möglichkeiten der Zusammensetzung. Die Repräsentation der Ressource inkludiert alle relevanten Werte der referenzierten Ressource oder es wird eine Referenz zu der Ressource eingefügt. Es wird nicht vorgeschrieben, in welcher Form diese Referenz ausfällt. Laut dem erstem Grundprinzip muss die Referenz allerdings eindeutig sein. Die Form kann beispielsweise eine Integer-ID oder eine URL sein. Dieses Prinzip wird oft als ''HATEOAS'' beschrieben. Das Akronym steht für ''Hypermedia as the engine of application state''. Es meint, dass der Applikationsfluss über die Verknüpfungen in den Repräsentationen von Ressourcen gesteuert wird. Diese Verknüpfung kann auch ein Statusübergang darstellen.\\\\% todo state\n" +
                "Der REST-Architekturstil gibt eine uniforme Schnittstelle vor. Es werden ein fester Satz von Methoden verwendet, um mit Ressource zu interagieren oder diese zu manipulieren. Dies bedeutet nicht, dass jede Ressource auch jegliche Art der Manipulation unterstützen muss. Es dürfen sehr wohl Ressource existieren, die mit denen nur lesend interagiert werden kann. Bei Schreibzugriff wird ein Fehler zurückgegeben. Die Methodendefinitonen der HTTP/1.1 Spezifikation \\cite{http11} bilden eine solche uniforme Schnittstelle. Vorweg werden zwei Eigenschaften von Methoden definiert, die es wert sind für alle Methoden zu betrachten. Die erste Eigenschaft kennzeichnet, ob eine Methode sicher (engl. safe) ist. Dies ist in diesem Fall so definiert, dass eine entsprechende Methode keine Nebeneffekte hat und ein Nutzer damit keine Verpflichtungen eingeht. Die zweite Eigenschaft der Methoden ist Idempotenz. Das bedeutet, dass wiederholte identische Anfragen die selbem Nebeneffekte haben. Der Zustand des Servers ist nach mehreren Anfragen gleich dem Zustand nach einer Anfrage. Eine sichere Methode ist damit implizit idempotent. Denn eine Methode, die keine Nebeneffekte ausweist und damit den Serverzustand gar nicht verändert, kann auch bei wiederholtem Anfragen Veränderung auslösen. Es ist wichtig anzumerken, dass diese Aussagen in der HTTP Spezifikation keine Garantie dafür sind, dass die Regelung in einer konkreten Implementierung eingehalten sind. Die grundsätzlichste Methode ist ''GET''. Sie bedeutet ein Abfragen einer Repräsentation einer Ressource, die mittels der angefragter URI identifiziert wird. Die Semantik der Methoden verändert sich, sobald die Ressource Caching unterstützt. In diesem Fall muss die Anfrage nicht an den Server geschickt werden, sondern es kann auf die zwischengespeicherte Instanz zurückgegriffen werden. Die Methode ist sicher und damit idempotent, da es sich um eine reine Abfrage handelt. Die Methode ''HEAD'' ist nahezu identisch mit ''GET'', der Server darf allerdings nur den Header der Antwort zurückgeben. Die Header müssen denen einer ''GET''-Anfrage gleichen. Die nächste Methode der Schnittstelle ist ''PUT''. Diese ist dazu gedacht, eine Ressource anzulegen oder zu aktualisieren, falls die Ressource bereits existiert. Im Fall einer Erstellung einer neuen Ressource muss der Server mit Status ''201 Created'' antworten. Bei Aktualisierung sollte mit 200 OK oder 204 No Content geantwortet werden. Die Methode ist nicht sicher, aber idempotent. Durch Anlegen oder Aktualisieren einer Ressource geht der Nutzer gegebenenfalls eine Verpflichtung ein. Idempotenz ist allerdings gewahrt, da der Zustand des Servers nach erneutem Anfragen gleich ist. Bei der ersten Anfrage wird die Ressource erstellt. Der Zustand wird vereinfacht durch Existenz genau dieser Ressource abgebildet. Nach erneutem Abschicken der exakt gleichen Anfrage, verändert sich die Ressource nicht. Der Zustand bleibt bestehen.\n" +
                "Die Methode ''DELETE'' verhält sich ähnlich. Wie der Name sagt, ist sie dazu gedacht, die Ressource, die über die URI identifiziert ist, zu löschen. Das Verhalten ist ebenfalls idempotent, da ein zweites Abschicken der gleichen Lösch-Anfrage zwar keinen Effekt mehr hat, aber ebenfalls keine Veränderung hervorruft. Die einzige nicht-idempotente Methode ist ''POST''. Laut HTTP Spezifikation ist sie dazu gedacht, eine untergeordnete Ressource anzulegen. Ein klassischen Beispiel ist das Senden einer Nachricht an eine Pinnwand. Das erneute Abschicken für zum Anlegen einer weiteren Nachricht. \\\\\n" +
                "Mit den Verben ''GET'', ''PUT'', ''DELETE'' und ''POST'' bietet die HTTP Spezifikation alle notwendigen Methoden für eine CRUD-Schnittstelle. Es lässt sich jegliche Art von Datenmanipulation damit abbilden. Ähnlich wie bei der Methode ''HEAD'' dient die nächste dem Abruf von Metadaten. Mit der Methode ''OPTIONS'' lassen sich die Kommunikationsoptionen mit einer Ressource abrufen. Der Server teilt dem Client die Methoden mit, die die spezifische Ressource unterstützt. Diese Information ist im Header ''Allow'' der Antwort zu finden. Die Anfrage sowie die Antwort kann einen Nachrichtenrumpf enthalten. Die Spezifikation geht allerdings nicht auf dessen Ausprägung und Verwendung ein. Es wird lediglich nicht ausgeschlossen, um die Erweiterbarkeit der Methode herzustellen. Besonders zu betrachten ist eine ''OPTIONS''-Anfrage an die URI ''*''. Diese Anfrage ist als reiner Server-Ping zu verstehen. Eine weitere Besonderheit bildet die Kopfzeile ''Max-Forwards''. Falls die Anfrage über einen oder mehrere Proxy-Server geschickt wird, müssen all diese den Header auswerten. Wenn der Wert 0 beträgt, darf die Anfrage nicht weitergeleitet werden. Stattdessen muss der Proxy-Server seine eigenen Kommunikationsoptions zurückliefern. Bei Weiterleiten der Nachricht, also Max-Forwards \\textgreater 0, muss der Proxy den Wert dekrementieren. \\\\\n" +
                "Die Methode TRACE dient Test- oder diagnostischen Zwecken bei Transport über einen oder mehrere Proxy-Server. Es ermöglicht einem Client, die Anfrage zu untersuchen, wie sie bei dem endgültigen Empfänger ankommt. Im Via-Header finden sich Informationen über die Proxy-Server, die die Anfrage weitergeleitet haben. In der Realität ist die Methode allerdings fast nie unterstützt. Hauptgrund dafür ist ein Sicherheitsrisiko durch einen Cross-site tracing \\cite{cst}-Angriff. Dabei war es Angreifern möglich, Cookies an ungewollte Webseiten mitzuschicken.\\\\\n" +
                "OPTIONS und TRACE sollen gemäß Spezifikation keine Nebeneffekte haben und sind damit sicher und idempotent. Die letzte Methode CONNECT dient des SSL Tunneling auf Proxy-Servern.";
        long start = System.currentTimeMillis();
        long nonce = bc.mineSeq(data);
        System.out.println("Seq: Found " + nonce + " after " + (System.currentTimeMillis() - start));
        start = System.currentTimeMillis();
        nonce = bc.mineParallel(data, 8);
        System.out.println("Parallel: Found " + nonce + " after " + (System.currentTimeMillis() - start));

    }


}
