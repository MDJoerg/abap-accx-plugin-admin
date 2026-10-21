"! <p class="shorttext synchronized">Access Explorer: incremental PFCG role change</p>
"! Changes an existing single role the way PFCG does (decision E10, stage 3):
"! menu changes with the PFCG menu API, authorization data in merge mode
"! (proposals of new menu entries added, the role's own maintenance kept),
"! manual values, open fields, profile generation. Unlike ZIF_ACCX_ROLE_WRITER
"! it never rebuilds a role. apply commits (the PFCG menu API saves with COMMIT).
"! For composite roles it adds or removes single roles, with the user comparison.
"! Changes of a reference role are passed on to its derived roles. New single
"! roles are created first, empty or as a copy of another single role.
INTERFACE zif_accx_role_changer PUBLIC.

  TYPES: BEGIN OF ty_catalog,
           id    TYPE string,
           "! menu node text
           title TYPE string,
         END OF ty_catalog,
         ty_catalogs TYPE STANDARD TABLE OF ty_catalog WITH EMPTY KEY.

  TYPES: BEGIN OF ty_value,
           object TYPE xuobject,
           field  TYPE xufield,
           low    TYPE xuval,
           high   TYPE xuval,
         END OF ty_value,
         ty_values TYPE STANDARD TABLE OF ty_value WITH EMPTY KEY.

  TYPES: BEGIN OF ty_change,
           role            TYPE agr_name,
           "! the role does not exist yet: create it (empty, or as a copy of copy_from) before the changes
           create          TYPE abap_bool,
           "! new role: single role to copy (menu, authorization data, texts; no users)
           copy_from       TYPE agr_name,
           "! new role: description (a copy keeps the description of its source without one)
           description     TYPE agr_title,
           add_tcodes      TYPE string_table,
           remove_tcodes   TYPE string_table,
           add_catalogs    TYPE ty_catalogs,
           "! catalogs removed with the authorization default nodes below them
           remove_catalogs TYPE ty_catalogs,
           "! manual values, merged as additional authorizations
           values          TYPE ty_values,
           "! values for open fields (empty field values) of active authorizations
           open_values     TYPE ty_values,
           "! composite role: single roles to add (the users of the composite role get them by the user comparison)
           add_roles       TYPE string_table,
           "! composite role: single roles to remove
           remove_roles    TYPE string_table,
           "! customizing request to record the role in; empty = as the client settings demand
           transport       TYPE trkorr,
         END OF ty_change.

  TYPES: BEGIN OF ty_step,
           step     TYPE string,
           ok       TYPE abap_bool,
           messages TYPE string_table,
         END OF ty_step,
         ty_steps TYPE STANDARD TABLE OF ty_step WITH EMPTY KEY.

  TYPES: BEGIN OF ty_outcome,
           steps     TYPE ty_steps,
           "! all steps ok
           ok        TYPE abap_bool,
           "! profile generated from the changed authorization data (composite roles: always, they have no profile of their own)
           generated TYPE abap_bool,
           "! open fields left, as OBJECT-FIELD; the profile is not generated while there are any
           open      TYPE string_table,
           "! request the role was recorded in
           transport TYPE trkorr,
           "! derived roles the change was passed on to (authorization data, profile, user comparison)
           derived   TYPE string_table,
         END OF ty_outcome.

  "! Hash of menu, single roles, derived roles, authorization data and profile state; changes whenever the role
  "! changes, also when a role that did not exist is created
  "! @parameter source | copy source of a new role; its state is part of the hash
  METHODS fingerprint
    IMPORTING !role         TYPE agr_name
              !source       TYPE agr_name OPTIONAL
    RETURNING VALUE(result) TYPE string.

  "! Open fields of active authorizations, as OBJECT-FIELD
  METHODS get_open_fields
    IMPORTING !role         TYPE agr_name
    RETURNING VALUE(result) TYPE string_table.

  "! Why the change cannot be recorded in the request; empty = fine or no request given
  METHODS check_transport
    IMPORTING !transport    TYPE trkorr
    RETURNING VALUE(result) TYPE string.

  "! Executes the change; refused in production clients and without S_USER_AGR 02 for the role (01 for a new role)
  METHODS apply
    IMPORTING !change       TYPE ty_change
    RETURNING VALUE(result) TYPE ty_outcome.

ENDINTERFACE.
