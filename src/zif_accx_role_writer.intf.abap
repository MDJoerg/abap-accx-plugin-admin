"! <p class="shorttext synchronized">Access Explorer: declarative PFCG role maintenance</p>
"! Internal API (decision E10, stage 1). A role is described as desired state;
"! plan compares it with the system, apply establishes it, verify re-checks.
"! Not part of the read-only core: lives in plugin package ZACCX_PLG_ADMIN.
"! apply does not COMMIT - the caller owns the LUW.
INTERFACE zif_accx_role_writer PUBLIC.

  TYPES: BEGIN OF ty_value,
           object TYPE xuobject,
           field  TYPE xufield,
           low    TYPE xuval,
           high   TYPE xuval,
         END OF ty_value,
         ty_values TYPE STANDARD TABLE OF ty_value WITH EMPTY KEY.
  TYPES ty_objects TYPE STANDARD TABLE OF xuobject WITH EMPTY KEY.
  TYPES ty_tcodes  TYPE STANDARD TABLE OF tcode WITH EMPTY KEY.
  TYPES ty_names   TYPE STANDARD TABLE OF agr_name WITH EMPTY KEY.

  " Desired state of one role
  TYPES: BEGIN OF ty_role_spec,
           name      TYPE agr_name,
           text      TYPE agr_title,
           composite TYPE abap_bool,
           "! single roles: menu transactions (SU24 proposals are taken from them)
           tcodes    TYPE ty_tcodes,
           "! composite roles: assigned single roles
           children  TYPE ty_names,
           "! objects whose SU24 proposals are suppressed - only VALUES remain active
           exclude   TYPE ty_objects,
           "! fixed values, one authorization per object
           values    TYPE ty_values,
         END OF ty_role_spec,
         ty_role_specs TYPE STANDARD TABLE OF ty_role_spec WITH EMPTY KEY.

  " Kinds of deviation between system and desired state
  CONSTANTS: BEGIN OF co_deviation,
               missing_role    TYPE string VALUE `missing_role`,
               missing_tcode   TYPE string VALUE `missing_tcode`,
               missing_child   TYPE string VALUE `missing_child`,
               missing_values  TYPE string VALUE `missing_values`,
               unwanted_values TYPE string VALUE `unwanted_values`,
               not_generated   TYPE string VALUE `not_generated`,
             END OF co_deviation.

  TYPES: BEGIN OF ty_deviation,
           role   TYPE agr_name,
           kind   TYPE string,
           detail TYPE string,
         END OF ty_deviation,
         ty_deviations TYPE STANDARD TABLE OF ty_deviation WITH EMPTY KEY.

  TYPES: BEGIN OF ty_step,
           role     TYPE agr_name,
           step     TYPE string,
           ok       TYPE abap_bool,
           messages TYPE string_table,
         END OF ty_step,
         ty_steps TYPE STANDARD TABLE OF ty_step WITH EMPTY KEY.

  "! Deviations of the system from the desired state (no changes)
  METHODS plan
    IMPORTING !spec         TYPE ty_role_spec
    RETURNING VALUE(result) TYPE ty_deviations.

  "! Establish the desired state; refused in productive clients and without
  "! S_USER_AGR 01/02 for the role
  METHODS apply
    IMPORTING !spec         TYPE ty_role_spec
    RETURNING VALUE(result) TYPE ty_steps.

  "! Deviations after apply; empty = role conforms
  METHODS verify
    IMPORTING !spec         TYPE ty_role_spec
    RETURNING VALUE(result) TYPE ty_deviations.

ENDINTERFACE.
