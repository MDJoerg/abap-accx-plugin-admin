"! <p class="shorttext synchronized">Access Explorer: role assignments of a user</p>
"! Changes one direct role assignment of a user (decision E10, stage 3): add
"! it, change its validity or remove it. The user's other assignments are kept
"! as they are, assignments through composite roles and HR organization are not
"! touched. apply commits; the profile comparison of the user is part of it.
INTERFACE zif_accx_assignment_writer PUBLIC.

  CONSTANTS: BEGIN OF co_action,
               assign TYPE string VALUE `assign`,
               remove TYPE string VALUE `remove`,
             END OF co_action.

  TYPES: BEGIN OF ty_assignment,
           role       TYPE agr_name,
           valid_from TYPE d,
           valid_to   TYPE d,
           "! assigned through the HR organization (not changed)
           org        TYPE abap_bool,
         END OF ty_assignment,
         ty_assignments TYPE STANDARD TABLE OF ty_assignment WITH EMPTY KEY.

  TYPES: BEGIN OF ty_change,
           user       TYPE xubname,
           role       TYPE agr_name,
           "! assign (new assignment or new validity of the existing one) or remove
           action     TYPE string,
           valid_from TYPE d,
           valid_to   TYPE d,
         END OF ty_change.

  TYPES: BEGIN OF ty_outcome,
           ok       TYPE abap_bool,
           messages TYPE string_table,
           "! direct assignments after the change
           after    TYPE ty_assignments,
           "! profiles in the user master after the change (UST04)
           profiles TYPE string_table,
         END OF ty_outcome.

  "! Direct role assignments of the user (as SU01 maintains them)
  METHODS get_assignments
    IMPORTING !user         TYPE xubname
    RETURNING VALUE(result) TYPE ty_assignments.

  "! Hash of all role assignments and profiles of the user; changes whenever they change
  METHODS fingerprint
    IMPORTING !user         TYPE xubname
    RETURNING VALUE(result) TYPE string.

  "! Executes the change; refused in production clients and when the caller changes own assignments
  METHODS apply
    IMPORTING !change       TYPE ty_change
    RETURNING VALUE(result) TYPE ty_outcome.

ENDINTERFACE.
