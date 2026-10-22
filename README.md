# abap-accx-plugin-admin

*[Deutsch](#deutsch) below.*

Optional write plugin of [Access Explorer (ACCX)](https://github.com/MDJoerg/abap-accx-base).
ABAP package `ZACCX_PLG_ADMIN`; it depends only on **abap-accx-base** (`ZACCX`).

It adds the tools `apply_role_change` (change or create a PFCG role) and `assign_role` (assign,
extend or remove a role of a user). Writing is guarded: the tools exist only in a server profile
with `ALLOW_WRITE`, never in a production client; every change is planned first (nothing is
changed), shown to the user, and executed only with the plan id and an explicit confirmation of
exactly that plan; critical authorizations need a separate acceptance; the results are verified
and logged.

## Install

1. Install **abap-accx-base** (`ZACCX`) and one adapter (`abap-accx-mcp2` or `abap-accx-mcp1`).
2. Pull this repository into package `ZACCX_PLG_ADMIN` with abapGit.
3. Run class `ZCL_ACCX_ADMIN_PLUGIN` with F9 in ADT. It activates the plugin for the profile
   `bc/access-admin` and creates that profile with `ALLOW_WRITE` (refused in productive clients).
4. Run the adapter class (`ZCL_ACCX_MCP2_SERVER` or `ZCL_ACCX_MCP1_SERVER`) with F9 again to
   register the new endpoint.

More (safeguards, tools, security, how the packages fit together) is documented in
**[abap-accx-base](https://github.com/MDJoerg/abap-accx-base)**.

## Deutsch

Optionales Schreib-Plugin von [Access Explorer (ACCX)](https://github.com/MDJoerg/abap-accx-base).
ABAP-Paket `ZACCX_PLG_ADMIN`; es hängt nur von **abap-accx-base** (`ZACCX`) ab.

Es ergänzt die Tools `apply_role_change` (PFCG-Rolle ändern oder anlegen) und `assign_role`
(einem Benutzer eine Rolle zuordnen, verlängern oder entziehen). Das Schreiben ist abgesichert: Die
Tools gibt es nur in einem Serverprofil mit `ALLOW_WRITE`, nie in einem Produktivmandanten; jede
Änderung wird zuerst geplant (es ändert sich nichts), dem Benutzer gezeigt und nur mit der Plan-ID
und einer ausdrücklichen Bestätigung genau dieses Plans ausgeführt; kritische Berechtigungen
brauchen eine eigene Zustimmung; die Ergebnisse werden geprüft und protokolliert.

### Installation

1. **abap-accx-base** (`ZACCX`) und einen Adapter (`abap-accx-mcp2` oder `abap-accx-mcp1`) installieren.
2. Dieses Repository mit abapGit in das Paket `ZACCX_PLG_ADMIN` ziehen.
3. Klasse `ZCL_ACCX_ADMIN_PLUGIN` in ADT mit F9 ausführen. Sie aktiviert das Plugin für das Profil
   `bc/access-admin` und legt dieses Profil mit `ALLOW_WRITE` an (in Produktivmandanten abgelehnt).
4. Die Adapter-Klasse (`ZCL_ACCX_MCP2_SERVER` oder `ZCL_ACCX_MCP1_SERVER`) erneut mit F9 ausführen,
   um den neuen Endpunkt zu registrieren.

Mehr (Schutzmaßnahmen, Tools, Sicherheit, Zusammenspiel der Pakete) steht in
**[abap-accx-base](https://github.com/MDJoerg/abap-accx-base)**.
