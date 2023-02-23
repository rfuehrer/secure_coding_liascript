<!--
author:   René Führer

email:    25303664+rfuehrer@users.noreply.github.com

version:  1.0.0

language: de

narrator: Deutsch Female

logo:     assets/preview.png
icon:     assets/logo-red.svg

comment:  Secure Coding - Cloud.

script:   https://cdnjs.cloudflare.com/ajax/libs/echarts/5.4.1/echarts-en.min.js

import:  https://raw.githubusercontent.com/liaScript/tensorflowjs_template/master/README.md

link:     assets/css/style.css
link:     assets/js/prismjs/prism.css
link:     assets/js/prismjs/prism.js

@onload

// hide the entire table of contents
//
// const slide = document.body.children[0]
// slide.style.left = "0px"
// slide.style.width = "100%"
// document.getElementById("lia-toc").style.display = "none"
// document.getElementById("lia-btn-toc").style.display = "none"
// document.getElementById("lia-toolbar-nav").style.left = "0px"

// hide only the toc elements by section id
const slides = [3,4,5,6]
const query = slides.map((id) => `a[href*="#${id}"]`).join(", ")
const links = document.getElementById("lia-toc").querySelectorAll(query);
// Iterate through the selected links and hide them
links.forEach(link => {
  link.style.display = 'none';
});

@end
-->

# Secure Coding

Diese Schulung bietet einen Überblick über sichere Softwareentwicklung mit anschließendem Test.


## Quiz "Cloud"

### Frage 1/6

Was ist die kritischste Schwachstelle in dem folgenden Code?

<!-- data-showGutter="true" -->
``` xml
<h2>Marathon Results <bean:write name="results" property="marathon.title" /></h2>
<c:choose>
  <c:when test="${param.refresh != null}">
    <script>
      // dynamic refresh interval to allow parameterized refresh rate by caller
      window.setTimeout('location.reload()', ${fn:escapeXml(param.refresh)});
    </script>
  </c:when>
  <c:otherwise>
      Show live results:
    <a href="/marathon/showResults.page?marathon=${results.marathon.id}&amp;refresh=20000">slow</a>
     |
    <a href="/marathon/showResults.page?marathon=${results.marathon.id}&amp;refresh=5000">quick</a>
  </c:otherwise>
</c:choose>

```

<!-- data-randomize data-max-trials="3" data-solution-button="2" -->
- [( )] Fehlende Eingabevalidierung
- [( )] Ungülte Typ-Konvertierung
- [(X)] Cross-Site Scripting
- [( )] Injection Vulnerabilty
- [( )] Cross-Site Request Forgery
- [( )] Unzureichende Ressourcen-Schließung
******************

Problem
=========

Reflektierte XSS-Schwachstellen entstehen, wenn Daten aus einer Anfrage kopiert und auf unsichere Weise in die unmittelbare Antwort der Anwendung übernommen werden. Ein Angreifer kann diese Schwachstelle nutzen, um eine Anfrage zu konstruieren, die, wenn sie von einem anderen Anwendungsbenutzer gestellt wird, dazu führt, dass vom Angreifer bereitgestellter JavaScript-Code im Browser des Benutzers im Kontext der Sitzung dieses Benutzers ausgeführt wird.

Der vom Angreifer bereitgestellte Code kann eine Vielzahl von Aktionen ausführen, wie z. B. den Diebstahl des Sitzungs-Tokens oder der Anmeldedaten des Opfers. Die Benutzer können auf verschiedene Weise dazu gebracht werden, die vom Angreifer erstellte Anfrage zu stellen. So kann der Angreifer dem Opfer beispielsweise einen Link mit einer bösartigen URL in einer E-Mail oder Sofortnachricht schicken.

Befindet sich dieselbe Anwendung in einer Domäne, die auf Cookies für andere, sicherheitskritischere Anwendungen zugreifen kann, könnte die Schwachstelle zum Angriff auf diese anderen Anwendungen genutzt werden und ist daher als hohes Risiko einzustufen. Bei vielen Anwendungen, z. B. solchen mit Online-Banking-Funktionen, sollte Cross-Site-Scripting immer als hohes Risiko eingestuft werden.

Auswirkung
==========

Angreifer können interaktiv auf einzelne Opfersitzungen zugreifen und Benutzerdaten stehlen oder verändern.

Vermeidung
==========

Die Eingaben sollten bei ihrem Eintreffen so streng wie möglich validiert werden, wenn man bedenkt, welche Art von Inhalt sie enthalten sollen. So sollten beispielsweise Personennamen aus alphabetischen und wenigen typografischen Zeichen bestehen und relativ kurz sein; ein Geburtsjahr sollte aus genau vier Ziffern bestehen; E-Mail-Adressen sollten einem genau definierten regulären Ausdruck entsprechen. Eingaben, die die Validierung nicht bestehen, sollten zurückgewiesen und nicht bereinigt werden.

Benutzereingaben sollten an jedem Punkt, an dem sie in Anwendungsantworten kopiert werden, HTML-kodiert werden. Alle HTML-Metazeichen, einschließlich spitzer Klammern, Anführungszeichen und Gleichheitszeichen, sollten durch die entsprechenden HTML-Entitäten (< > usw.) ersetzt werden.

In Fällen, in denen die Funktionalität der Anwendung es den Benutzern erlaubt, Inhalte unter Verwendung einer eingeschränkten Teilmenge von HTML-Tags und -Attributen zu verfassen (z. B. Blog-Kommentare mit ein wenig Formatierung), ist es notwendig, das gelieferte HTML zu analysieren, um zu überprüfen, dass es keine gefährliche Syntax verwendet (dies ist nicht trivial).

Bitte beachten Sie, dass die in diesem Bericht gezeigten Beweise nur eine Teilmenge enthalten und auch nicht alle Teile der Anwendung in der begrenzten Pentesting-Zeitspanne getestet wurden. Daher sollen alle Ausgabestellen der Anwendung auf Code-Ebene auf weitere XSS-Schwachstellen untersucht werden, die behoben werden müssen.

Referenzen
==========

[https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)

Schlechtes Beispiel
==========

Zeile 6 liest nicht vertrauenswürdige Daten aus der Anfrage und gibt sie direkt in den JavaScript-Kontext aus. Die XML-Kodierung über fn:escapeXml würde klassische HTML-Kontexte lösen, aber hier ist es (leider) die falsche Ausgabekodierung, da diese Stelle im JavaScript-Kontext liegt.

<!-- data-showGutter="true" data-marker="5 45 5 76 error text;" -->
``` xml
<h2>Marathon Results <bean:write name="results" property="marathon.title" /></h2>
<c:choose>
  <c:when test="${param.refresh != null}">
    <script>
      // dynamic refresh interval to allow parameterized refresh rate by caller
      window.setTimeout('location.reload()', ${fn:escapeXml(param.refresh)});
    </script>
  </c:when>
  <c:otherwise>
      Show live results:
    <a href="/marathon/showResults.page?marathon=${results.marathon.id}&amp;refresh=20000">slow</a>
     |
    <a href="/marathon/showResults.page?marathon=${results.marathon.id}&amp;refresh=5000">quick</a>
  </c:otherwise>
</c:choose>

```
******************

### Frage 2/6

Was ist die kritischste Schwachstelle in dem folgenden Code?

<!-- data-showGutter="true" -->
``` 
Runner runner = null;
Connection connection = null;
try {
  connection = DAOUtils.getConnection();
  RunnerDAO runnerDAO = new RunnerDAO(connection);
  RunnerForm runnerForm = (RunnerForm)form;
  runner = new Runner( runnerForm.getId(), runnerForm.getUsername(), runnerForm.getFirstname(),
    runnerForm.getLastname(), runnerForm.getStreet(), runnerForm.getZip(),
    runnerForm.getCity(), runnerForm.getDateOfBirthAsDate(), runnerForm.getCreditcardNumber() );
  runnerDAO.updateRunner(runner);
  runner = runnerDAO.loadRunner(runner.getId());
  String marshalledBase64 = request.getParameter("state");
  if (marshalledBase64 != null && marshalledBase64.trim().length() > 0) {
    String xml = new String(Base64.getDecoder().decode(marshalledBase64.trim()));
    XStream xstream = new XStream();
    Map stateMap = (Map) xstream.fromXML(xml);
  }
} finally {
  if (connection != null) connection.close();
}
request.setAttribute("runner", runner);
request.setAttribute("UpdateResultMessage", "<b>Your data has been saved</b>");

```

<!-- data-randomize data-max-trials="3" data-solution-button="2" -->
- [( )] Sitzungsfixierung
- [( )] Injektionsschwachstelle
- [(X)] Nicht vertrauenswürdige Deserialisierung
- [( )] Fehlende Ausgabekodierung
- [( )] Ungültige Typkonvertierung
- [( )] Unzureichender Ressourcen-Abschluss
******************

This code is vulnerable to Untrusted XStream Deserialization: XML data is read from the request and unmarshalled using XStream without a whitelist of types allowed to deserialize. 

Problem
=========

Unter Serialisierung versteht man die Umwandlung eines Objekts in ein Datenformat, das später wiederhergestellt werden kann. Häufig werden Objekte serialisiert, um sie zu speichern oder als Teil der Kommunikation zu versenden. Die Deserialisierung ist die Umkehrung dieses Prozesses, bei der strukturierte Daten aus einem bestimmten Format in ein Objekt umgewandelt werden. Das gängigste Datenformat für die Serialisierung von Daten ist heute JSON. Davor war es XML.

Viele Programmiersprachen bieten jedoch eine native Funktion zur Serialisierung von Objekten. Diese nativen Formate bieten in der Regel mehr Funktionen als JSON oder XML, einschließlich der Anpassbarkeit des Serialisierungsprozesses. Leider können die Funktionen dieser nativen Deserialisierungsmechanismen für bösartige Zwecke missbraucht werden, wenn sie mit nicht vertrauenswürdigen Daten arbeiten. Es wurde festgestellt, dass Angriffe auf Deserialisierer Denial-of-Service-, Zugriffskontroll- und Remote-Code-Execution (RCE)-Angriffe ermöglichen. 

Auswirkung
==========

Entfernte Code-Ausführung (Remote Code Execution, RCE): Angreifer können Code auf den betroffenen Servern ausführen, was zu einem tieferen Eindringen in das System führt. 

Vermeidung
==========

Ziehen Sie in Erwägung, entweder die Deserialisierung zu entfernen (dies erfordert oft eine Änderung der Architektur) oder zumindest sicherzustellen, dass nur vertrauenswürdige Daten deserialisiert werden (z. B. durch kryptografische Signierung).

Alternativ können Sie eine strenge Whitelist der zulässigen Typen für die Deserialisierung mit Hilfe der XStream-Deserialisierungs-Whitelist-Konfiguration anwenden (was leider immer noch oft Risiken für Denial-of-Service birgt) oder zu einer anderen XML-Unmarshalling-Technologie (wie z. B. JAXB) wechseln, die keine Deserialisierungstechniken unter der Haube verwendet.

Referenzen
==========

- https://christian-schneider.net/JavaDeserializationSecurityFAQ.html
- https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html
- https://x-stream.github.io/CVE-2020-26217.html
- https://x-stream.github.io/security.html#framework
- https://github.com/cschneider4711/SWAT



Schlechtes Beispiel
==========

In Zeile 12 wird nicht vertrauenswürdiges XML aus der Anfrage gelesen und in Zeile 16 wird XStream verwendet, um diesen Payload zu deserialisieren, ohne dass eine strenge Whitelist der zulässigen zu deserialisierenden Typen festgelegt wurde.

<!-- data-firstLineNumber="1" data-showGutter="true" data-marker="11 28 11 57 error text; 15 25 15 33 error text;" -->
```
Runner runner = null;
Connection connection = null;
try {
  connection = DAOUtils.getConnection();
  RunnerDAO runnerDAO = new RunnerDAO(connection);
  RunnerForm runnerForm = (RunnerForm)form;
  runner = new Runner( runnerForm.getId(), runnerForm.getUsername(), runnerForm.getFirstname(),
    runnerForm.getLastname(), runnerForm.getStreet(), runnerForm.getZip(),
    runnerForm.getCity(), runnerForm.getDateOfBirthAsDate(), runnerForm.getCreditcardNumber() );
  runnerDAO.updateRunner(runner);
  runner = runnerDAO.loadRunner(runner.getId());
  String marshalledBase64 = request.getParameter("state");
  if (marshalledBase64 != null && marshalledBase64.trim().length() > 0) {
    String xml = new String(Base64.getDecoder().decode(marshalledBase64.trim()));
    XStream xstream = new XStream();
    Map stateMap = (Map) xstream.fromXML(xml);
  }
} finally {
  if (connection != null) connection.close();
}
request.setAttribute("runner", runner);
request.setAttribute("UpdateResultMessage", "<b>Your data has been saved</b>");

```
******************

### Frage 3/6

Was ist die kritischste Schwachstelle in dem folgenden Code?

<!-- data-showGutter="true" -->
``` 
@GET
@Path("/images/{image}")
@Produces("images/*")
public Response getImage(@javax.ws.rs.PathParam("image") String image) {
    File file = new File("resources/images/", image);
    if (!file.exists()) {
        return Response.status(Status.NOT_FOUND).build();
    }
    return Response.ok().entity(new FileInputStream(file)).build();
}

```

<!-- data-randomize data-max-trials="3" data-solution-button="2" -->
- [(X)] Pfadüberquerung
- [( )] Fehlende Prüfung des Dateityps
- [( )] Ungültige Typkonvertierung
- [( )] Unzureichender Ressourcen-Abschluss
- [( )] Denial of Service
- [( )] Injektionsschwachstelle
- [( )] Fehlende Verschlüsselung
******************

Dieser Code ist anfällig für Path Traversal: Der Anforderungsparameter "image" wird innerhalb einer Dateisystemoperation verwendet. 

Problem
=========

Dateipfadüberquerungsschwachstellen entstehen, wenn benutzerkontrollierbare Daten innerhalb einer Dateisystemoperation auf unsichere Weise verwendet werden. Normalerweise wird ein vom Benutzer angegebener Dateiname an ein Verzeichnispräfix angehängt, um den Inhalt einer Datei zu lesen oder zu schreiben. Ist ein Angreifer verwundbar, kann er Pfad-Traversal-Sequenzen (unter Verwendung von Punkt-Punkt-Schrägstrich-Zeichen) eingeben, um aus dem vorgesehenen Verzeichnis auszubrechen und Dateien an anderer Stelle im Dateisystem zu lesen oder zu schreiben.

Dies ist in der Regel eine sehr schwerwiegende Sicherheitslücke, die es einem Angreifer ermöglicht, auf sensible Dateien zuzugreifen, die Konfigurationsdaten, Kennwörter, Datenbankeinträge, Protokolldaten, Quellcode, Programmskripte und Binärdateien enthalten. 

Auswirkung
==========

Angreifer können (sensible) Dateien aus dem Dateisystem der Anwendung lesen. Auf Linux-Systemen gehören dazu auch Umgebungsvariablen, Kommandozeilenargumente, stdout usw. über das virtuelle "/proc"-Dateisystem (wie der Zugriff auf `../../../../../proc/self/environ`), wodurch ebenfalls Geheimnisse preisgegeben werden können. 

Vermeidung
==========

Idealerweise sollte die Anwendungsfunktionalität so gestaltet sein, dass vom Benutzer kontrollierbare Daten nicht an Dateisystemoperationen übergeben werden müssen. Dies kann in der Regel dadurch erreicht werden, dass bekannte Dateien über eine Indexnummer und nicht über ihren Namen referenziert werden, und dass von der Anwendung generierte Dateinamen verwendet werden, um vom Benutzer eingegebene Dateiinhalte zu speichern. Wenn es als unvermeidlich angesehen wird, benutzerkontrollierbare Daten an Dateisystemoperationen weiterzugeben, können drei Verteidigungsschichten eingesetzt werden, um Path-Traversal-Angriffe zu verhindern:

1) Benutzerkontrollierbare Daten sollten streng überprüft werden, bevor sie an Dateisystemoperationen weitergegeben werden. Insbesondere sollten Eingaben, die Punkt-Punkt-Sequenzen enthalten, blockiert werden.

2) Nach der Validierung von Benutzereingaben kann die Anwendung eine geeignete Dateisystem-API verwenden, um zu überprüfen, ob sich die Datei, auf die zugegriffen werden soll, tatsächlich in dem von der Anwendung verwendeten Basisverzeichnis befindet. In Java kann dies erreicht werden, indem ein java.io.File-Objekt mit dem vom Benutzer angegebenen Dateinamen instanziiert und dann die Methode getCanonicalPath für dieses Objekt aufgerufen wird. Wenn die von dieser Methode zurückgegebene Zeichenkette nicht mit dem Namen des Startverzeichnisses beginnt, hat der Benutzer die Eingabefilter der Anwendung irgendwie umgangen, und die Anfrage sollte zurückgewiesen werden. In ASP.NET kann dieselbe Prüfung durchgeführt werden, indem der vom Benutzer angegebene Dateiname an die Methode System.Io.Path.GetFullPath übergeben und die zurückgegebene Zeichenkette auf dieselbe Weise wie für Java beschrieben geprüft wird.

3) Das Verzeichnis, in dem Dateien gespeichert werden, auf die mit benutzerkontrollierbaren Daten zugegriffen wird, kann sich auf einem von anderen sensiblen Anwendungs- und Betriebssystemdateien getrennten logischen Datenträger befinden, so dass diese nicht über Path-Traversal-Angriffe erreicht werden können. In Unix-basierten Systemen kann dies durch ein chroot-Dateisystem erreicht werden; unter Windows kann dies durch das Mounten des Basisverzeichnisses als neues logisches Laufwerk und die Verwendung des zugehörigen Laufwerksbuchstabens für den Zugriff auf dessen Inhalt erreicht werden. Auch Container können die Sichtbarkeit der äußeren Dateisystemform innerhalb des Containers reduzieren.

Referenzen
==========

- https://owasp.org/www-community/attacks/Path_Traversal

Schlechtes Beispiel
==========

In Zeile 5 wird eine Datei geöffnet, um ihren Inhalt zu lesen. Wenn ein ungefilterter Parameter an diese Datei-API übergeben wird, können Dateien von einem beliebigen Ort im Dateisystem gelesen werden. Angreifer können Nutzdaten wie `../../../../../../etc/passwd` (und Ableitungen davon) verwenden, um auf Dateien außerhalb des erwarteten Verzeichnisses zuzugreifen.

<!-- data-firstLineNumber="1" data-showGutter="true" data-marker="4 20 4 52 error text;" -->
```
@GET
@Path("/images/{image}")
@Produces("images/*")
public Response getImage(@javax.ws.rs.PathParam("image") String image) {
    File file = new File("resources/images/", image);
    if (!file.exists()) {
        return Response.status(Status.NOT_FOUND).build();
    }
    return Response.ok().entity(new FileInputStream(file)).build();
}

```
******************

### Frage 4/6

Was ist die kritischste Schwachstelle in dem folgenden Code?

<!-- data-showGutter="true" -->
``` 
import scala.util.Random

def generateSecretToken() {
    val result = Seq.fill(16)(Random.nextInt)
    return result.map("%02x" format _).mkString
}

```

<!-- data-randomize data-max-trials="3" data-solution-button="2" -->
- [( )] Unzureichender Ressourcenabschluss
- [(X)] Unsichere Zufälligkeit
- [( )] Ungültige Typenzuordnung
- [( )] Fehlende Längenprüfung
- [( )] Überschreiben des Puffers
- [( )] Unkontrollierte Formatzeichenfolge
- [( )] Denial of Service
******************

Dieser Code ist anfällig für Insecure Randomness: Die Pseudo-Zufallswerte aus `scala.util.Random` sind vorhersehbar und nicht kryptographisch sicher. 

Problem
=========

Die Verwendung eines vorhersagbaren Zufallswertes kann zu Schwachstellen führen, wenn er in bestimmten sicherheitskritischen Kontexten verwendet wird. Zum Beispiel, wenn der Wert verwendet wird für:

- Sicherheits-Token: Vorhersagbare Token können zu Angriffen führen, da ein Angreifer den Wert des Tokens kennt.
- Gutschein-Codes: Vorhersagbare Gutscheine können zu Angriffen führen, da ein Angreifer die Werte gültiger Gutscheine kennt.
- Token zum Zurücksetzen von Passwörtern (per E-Mail verschickt): Vorhersehbare Passwort-Tokens können zu einer Kontoübernahme führen, da ein Angreifer die URL des Formulars "Passwort ändern" erraten wird.
- jeder andere geheime Wert

Auswirkung
==========

Angreifer können Aktionen ausführen, die sonst nicht möglich wären, oder andere Konten kompromittieren. 

Vermeidung
==========

Eine schnelle Lösung könnte darin bestehen, die Verwendung von scala.util.Random durch etwas Stärkeres zu ersetzen, wie java.security.SecureRandom. 

Referenzen
==========

- https://owasp.org/www-community/vulnerabilities/Insecure_Randomness

Schlechtes Beispiel
==========

Zeile 4 verwendet einen vorhersagbaren Pseudozufallszahlengenerator (`scala.util.Random`), um ein sicherheitsrelevantes Token zu erzeugen.

<!-- data-firstLineNumber="1" data-showGutter="true" data-marker="3 30 3 37 error text;" -->
```
import scala.util.Random

def generateSecretToken() {
    val result = Seq.fill(16)(Random.nextInt)
    return result.map("%02x" format _).mkString
}

```
******************

## Abschluss

<script style="display: block" modify="false">

const gauge = {
  tooltip: {
    formatter: '{a} <br/>{b} : {c}%'
  },
  series: [
    {
      type: 'gauge',
      axisLine: {
        lineStyle: {
          width: 30,
          color: [
            [0.8, '#efefef'],
            [1, '#F08080']
          ]
        }
      },
      pointer: {
        itemStyle: {
          color: '#292929'
        }
      },
      axisTick: {
        distance: -30,
        length: 8,
        lineStyle: {
          color: '#000000',
          width: 2
        }
      },
      splitLine: {
        distance: -30,
        length: 30,
        lineStyle: {
          color: '#000000',
          width: 4
        }
      },
      axisLabel: {
        color: '#000000',
        distance: 40,
        fontSize: 20
      },
      detail: {
        valueAnimation: true,
        formatter: '{value}',
        color: '#292929'
      },
      data: [
        {
          value: Math.round(window.SCORE*100) || 0,
          name: '% PUNKTE'
        }
      ]
    }
  ]
};

`HTML: <lia-chart option='${JSON.stringify(gauge)}'></lia-chart>`
</script>
