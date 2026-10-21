"! <p class="shorttext synchronized">Access Explorer: PFCG role writer (dark API)</p>
"! Uses the PFCG dark APIs (PRGN_RFC_*, PRGN_AUTO_GENERATE_PROFILE_NEW).
"! Per single role (verified on A4H 2026-10-20):
"!  1. mode F - complete rebuild from the SU24 proposals of the menu
"!  2. mode X - merge of the fixed VALUES (re-merges proposals of excluded objects)
"!  3. deactivate (DELETED flag in AGR_1250/AGR_1251) every authorization of an
"!     excluded object whose values differ from VALUES - stability class C
"!  4. generate the profile from the stored data without merging
CLASS zcl_accx_role_writer DEFINITION PUBLIC CREATE PUBLIC.

  PUBLIC SECTION.
    INTERFACES zif_accx_role_writer.

  PROTECTED SECTION.
    TYPES: BEGIN OF ty_auth_set,
             auth      TYPE xuauth,
             signature TYPE string,
           END OF ty_auth_set,
           ty_auth_sets TYPE STANDARD TABLE OF ty_auth_set WITH EMPTY KEY.

    METHODS compare
      IMPORTING !spec         TYPE zif_accx_role_writer=>ty_role_spec
      RETURNING VALUE(result) TYPE zif_accx_role_writer=>ty_deviations.

    "! Problem text if the change is not allowed, empty otherwise
    METHODS check_allowed
      IMPORTING !spec         TYPE zif_accx_role_writer=>ty_role_spec
                !create       TYPE abap_bool
      RETURNING VALUE(result) TYPE string.

    "! Sorted signature of the fixed values of one object
    METHODS wanted_signature
      IMPORTING !spec         TYPE zif_accx_role_writer=>ty_role_spec
                !object       TYPE xuobject
      RETURNING VALUE(result) TYPE string.

    "! Signatures of all active authorizations of one object in the role
    METHODS active_signatures
      IMPORTING !role         TYPE agr_name
                !object       TYPE xuobject
      RETURNING VALUE(result) TYPE ty_auth_sets.

    METHODS deactivate_foreign
      IMPORTING !spec  TYPE zif_accx_role_writer=>ty_role_spec
      CHANGING  !steps TYPE zif_accx_role_writer=>ty_steps.

    METHODS add_step
      IMPORTING !role   TYPE agr_name
                !step   TYPE string
                !subrc  TYPE sysubrc
                !return TYPE bapiret2_t OPTIONAL
      CHANGING  !steps  TYPE zif_accx_role_writer=>ty_steps.

ENDCLASS.

CLASS zcl_accx_role_writer IMPLEMENTATION.

  METHOD zif_accx_role_writer~plan.
    result = compare( spec ).
  ENDMETHOD.

  METHOD zif_accx_role_writer~verify.
    result = compare( spec ).
  ENDMETHOD.

  METHOD zif_accx_role_writer~apply.
    DATA return   TYPE STANDARD TABLE OF bapiret2.
    DATA tcodes   TYPE STANDARD TABLE OF ssm_tcodes.
    DATA menu     TYPE STANDARD TABLE OF twbtcode.
    DATA children TYPE STANDARD TABLE OF agr_txt.
    DATA manual   TYPE STANDARD TABLE OF tvordata.
    DATA none     TYPE STANDARD TABLE OF tvordata.
    DATA excluded TYPE susr_t_sel_opt_object.

    SELECT SINGLE @abap_true FROM agr_define WHERE agr_name = @spec-name INTO @DATA(exists).

    DATA(problem) = check_allowed( spec = spec create = xsdbool( exists = abap_false ) ).
    IF problem IS NOT INITIAL.
      APPEND VALUE #( role = spec-name step = `precondition` ok = abap_false messages = VALUE #( ( problem ) ) ) TO result.
      RETURN.
    ENDIF.

    IF spec-composite = abap_true.
      IF exists = abap_false.
        CALL FUNCTION 'PRGN_RFC_CREATE_AGR_MULTIPLE'
          EXPORTING
            activity_group      = spec-name
            activity_group_text = spec-text
            collective_agr      = 'X'
            no_dialog           = 'X'
          TABLES
            return              = return
          EXCEPTIONS
            OTHERS              = 1.
        add_step( EXPORTING role = spec-name step = `create composite role` subrc = sy-subrc return = return
                  CHANGING  steps = result ).
      ENDIF.
      children = VALUE #( FOR child IN spec-children ( agr_name = child ) ).
      CLEAR return.
      CALL FUNCTION 'PRGN_RFC_ADD_AGRS_TO_COLL_AGR'
        EXPORTING
          activity_group  = spec-name
        TABLES
          activity_groups = children
          return          = return
        EXCEPTIONS
          OTHERS          = 1.
      add_step( EXPORTING role = spec-name step = `assign single roles` subrc = sy-subrc return = return
                CHANGING  steps = result ).
      RETURN.
    ENDIF.

    IF exists = abap_false.
      tcodes = VALUE #( FOR tcode IN spec-tcodes ( tcode = tcode ) ).
      CALL FUNCTION 'PRGN_RFC_CREATE_ACTIVITY_GROUP'
        EXPORTING
          activity_group        = spec-name
          activity_group_text   = spec-text
          only_tcode_assignment = 'X'
        TABLES
          tcodes                = tcodes
          return                = return
        EXCEPTIONS
          OTHERS                = 1.
      add_step( EXPORTING role = spec-name step = `create role with menu` subrc = sy-subrc return = return
                CHANGING  steps = result ).
    ELSE.
      SELECT tcode FROM agr_tcodes WHERE agr_name = @spec-name AND type = 'TR' INTO TABLE @DATA(existing).
      LOOP AT spec-tcodes INTO DATA(wanted).
        IF NOT line_exists( existing[ tcode = wanted ] ).
          APPEND VALUE #( tcode = wanted ) TO menu.
        ENDIF.
      ENDLOOP.
      IF menu IS NOT INITIAL.
        CALL FUNCTION 'PRGN_RFC_CHANGE_TRANSACTIONS'
          EXPORTING
            activity_group = spec-name
            no_dialog      = 'X'
          TABLES
            tcodes         = menu
            return         = return
          EXCEPTIONS
            OTHERS         = 1.
        add_step( EXPORTING role = spec-name step = `add menu transactions` subrc = sy-subrc return = return
                  CHANGING  steps = result ).
      ENDIF.
    ENDIF.

    manual   = VALUE #( FOR value IN spec-values ( object = value-object field = value-field low = value-low high = value-high ) ).
    excluded = VALUE #( FOR object IN spec-exclude ( sign = 'I' option = 'EQ' low = object ) ).

    " 1 - complete rebuild from SU24 proposals
    CLEAR return.
    CALL FUNCTION 'PRGN_AUTO_GENERATE_PROFILE_NEW'
      EXPORTING
        activity_group              = spec-name
        no_dialog                   = 'X'
        rebuild_auth_data           = 'F'
        org_levels_with_star        = 'X'
        fill_empty_fields_with_star = 'X'
        generate_profile            = 'X'
      TABLES
        return                      = return
        manual_auths                = none
        objcts_excl                 = excluded
      EXCEPTIONS
        OTHERS                      = 1.
    add_step( EXPORTING role = spec-name step = `1 rebuild from SU24 (mode F)` subrc = sy-subrc return = return
              CHANGING  steps = result ).

    " 2 - merge fixed values
    IF manual IS NOT INITIAL.
      CLEAR return.
      CALL FUNCTION 'PRGN_AUTO_GENERATE_PROFILE_NEW'
        EXPORTING
          activity_group              = spec-name
          no_dialog                   = 'X'
          rebuild_auth_data           = 'X'
          org_levels_with_star        = 'X'
          fill_empty_fields_with_star = 'X'
          generate_profile            = 'X'
        TABLES
          return                      = return
          manual_auths                = manual
          objcts_excl                 = excluded
        EXCEPTIONS
          OTHERS                      = 1.
      add_step( EXPORTING role = spec-name step = `2 merge fixed values (mode X)` subrc = sy-subrc return = return
                CHANGING  steps = result ).
    ENDIF.

    " 3 + 4 - deactivate foreign authorizations of excluded objects, generate
    IF spec-exclude IS NOT INITIAL.
      deactivate_foreign( EXPORTING spec = spec CHANGING steps = result ).
      CLEAR return.
      CALL FUNCTION 'PRGN_AUTO_GENERATE_PROFILE_NEW'
        EXPORTING
          activity_group              = spec-name
          no_dialog                   = 'X'
          rebuild_auth_data           = ' '
          fill_empty_fields_with_star = ' '
          generate_profile            = 'X'
        TABLES
          return                      = return
        EXCEPTIONS
          OTHERS                      = 1.
      add_step( EXPORTING role = spec-name step = `4 generate profile (no merge)` subrc = sy-subrc return = return
                CHANGING  steps = result ).
    ENDIF.
  ENDMETHOD.

  METHOD compare.
    SELECT SINGLE @abap_true FROM agr_define WHERE agr_name = @spec-name INTO @DATA(exists).
    IF exists = abap_false.
      APPEND VALUE #( role = spec-name kind = zif_accx_role_writer=>co_deviation-missing_role detail = `role does not exist` ) TO result.
      RETURN.
    ENDIF.

    IF spec-composite = abap_true.
      SELECT child_agr FROM agr_agrs WHERE agr_name = @spec-name INTO TABLE @DATA(children).
      LOOP AT spec-children INTO DATA(child).
        IF NOT line_exists( children[ child_agr = child ] ).
          APPEND VALUE #( role = spec-name kind = zif_accx_role_writer=>co_deviation-missing_child detail = |{ child }| ) TO result.
        ENDIF.
      ENDLOOP.
      RETURN.
    ENDIF.

    SELECT tcode FROM agr_tcodes WHERE agr_name = @spec-name AND type = 'TR' INTO TABLE @DATA(tcodes).
    LOOP AT spec-tcodes INTO DATA(tcode).
      IF NOT line_exists( tcodes[ tcode = tcode ] ).
        APPEND VALUE #( role = spec-name kind = zif_accx_role_writer=>co_deviation-missing_tcode detail = |{ tcode }| ) TO result.
      ENDIF.
    ENDLOOP.

    DATA objects TYPE SORTED TABLE OF xuobject WITH UNIQUE KEY table_line.
    LOOP AT spec-values INTO DATA(value).
      INSERT value-object INTO TABLE objects.
    ENDLOOP.
    LOOP AT objects INTO DATA(object).
      DATA(wanted) = wanted_signature( spec = spec object = object ).
      DATA(actives) = active_signatures( role = spec-name object = object ).
      IF NOT line_exists( actives[ signature = wanted ] ).
        APPEND VALUE #( role = spec-name kind = zif_accx_role_writer=>co_deviation-missing_values detail = |{ object }: { wanted }| ) TO result.
      ENDIF.
    ENDLOOP.

    LOOP AT spec-exclude INTO object.
      wanted = wanted_signature( spec = spec object = object ).
      actives = active_signatures( role = spec-name object = object ).
      LOOP AT actives INTO DATA(active) WHERE signature <> wanted.
        APPEND VALUE #( role = spec-name kind = zif_accx_role_writer=>co_deviation-unwanted_values
                        detail = |{ object }/{ active-auth }: { active-signature }| ) TO result.
      ENDLOOP.
    ENDLOOP.

    SELECT SINGLE generated FROM agr_1016 WHERE agr_name = @spec-name INTO @DATA(generated).
    IF generated IS INITIAL.
      APPEND VALUE #( role = spec-name kind = zif_accx_role_writer=>co_deviation-not_generated detail = `profile not generated` ) TO result.
    ENDIF.
  ENDMETHOD.

  METHOD check_allowed.
    SELECT SINGLE cccategory FROM t000 WHERE mandt = @sy-mandt INTO @DATA(category).
    IF category = 'P'.
      result = |Client { sy-mandt } is a production client - role maintenance refused.|.
      RETURN.
    ENDIF.
    DATA(role) = spec-name.
    DATA(activity) = COND activ_auth( WHEN create = abap_true THEN '01' ELSE '02' ).
    AUTHORITY-CHECK OBJECT 'S_USER_AGR' ID 'ACT_GROUP' FIELD role ID 'ACTVT' FIELD activity.
    IF sy-subrc <> 0.
      result = |No authorization S_USER_AGR { activity } for role { role }.|.
    ENDIF.
  ENDMETHOD.

  METHOD wanted_signature.
    DATA(parts) = VALUE string_table( FOR value IN spec-values WHERE ( object = object )
                                      ( |{ value-field }={ value-low }-{ value-high }| ) ).
    SORT parts.
    result = concat_lines_of( table = parts sep = `;` ).
  ENDMETHOD.

  METHOD active_signatures.
    SELECT auth, field, low, high FROM agr_1251
      WHERE agr_name = @role AND object = @object AND deleted = @space
      INTO TABLE @DATA(rows).
    LOOP AT rows INTO DATA(row) GROUP BY row-auth INTO DATA(auth).
      DATA(parts) = VALUE string_table( FOR member IN GROUP auth ( |{ member-field }={ member-low }-{ member-high }| ) ).
      SORT parts.
      APPEND VALUE #( auth = auth signature = concat_lines_of( table = parts sep = `;` ) ) TO result.
    ENDLOOP.
  ENDMETHOD.

  METHOD deactivate_foreign.
    DATA(role) = spec-name.
    LOOP AT spec-exclude INTO DATA(object).
      DATA(wanted) = wanted_signature( spec = spec object = object ).
      DATA(actives) = active_signatures( role = role object = object ).
      LOOP AT actives INTO DATA(active) WHERE signature <> wanted.
        UPDATE agr_1251 SET deleted = 'X' WHERE agr_name = @role AND object = @object AND auth = @active-auth.
        UPDATE agr_1250 SET deleted = 'X' WHERE agr_name = @role AND object = @object AND auth = @active-auth.
        add_step( EXPORTING role = role step = |3 deactivate { object }/{ active-auth }| subrc = 0
                  CHANGING  steps = steps ).
      ENDLOOP.
    ENDLOOP.
  ENDMETHOD.

  METHOD add_step.
    DATA(step_entry) = VALUE zif_accx_role_writer=>ty_step( role = role step = step ok = xsdbool( subrc = 0 ) ).
    IF subrc <> 0.
      APPEND |{ sy-msgid }/{ sy-msgno } { sy-msgv1 } { sy-msgv2 } { sy-msgv3 } { sy-msgv4 }| TO step_entry-messages.
    ENDIF.
    LOOP AT return INTO DATA(message) WHERE type CA 'EAW'.
      APPEND |{ message-type } { message-id }/{ message-number }: { message-message }| TO step_entry-messages.
    ENDLOOP.
    APPEND step_entry TO steps.
  ENDMETHOD.

ENDCLASS.
