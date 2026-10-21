"! <p class="shorttext synchronized">Access Explorer: role assignments of a user</p>
"! BAPI_USER_GET_DETAIL reads the direct assignments, BAPI_USER_ACTGROUPS_ASSIGN
"! writes the complete list back (verified on A4H 2026-10-21: it replaces the
"! list, compares the user's profiles immediately and writes change documents
"! of object classes IDENTITY and PFCG). The BAPI checks the caller's
"! authorizations itself (S_USER_GRP, S_USER_AGR).
CLASS zcl_accx_assignment_writer DEFINITION PUBLIC CREATE PUBLIC.

  PUBLIC SECTION.
    INTERFACES zif_accx_assignment_writer.

ENDCLASS.

CLASS zcl_accx_assignment_writer IMPLEMENTATION.

  METHOD zif_accx_assignment_writer~get_assignments.
    DATA groups TYPE STANDARD TABLE OF bapiagr.
    DATA return TYPE STANDARD TABLE OF bapiret2.
    CALL FUNCTION 'BAPI_USER_GET_DETAIL'
      EXPORTING username       = user
      TABLES    activitygroups = groups
                return         = return.
    result = VALUE #( FOR g IN groups ( role = g-agr_name valid_from = g-from_dat valid_to = g-to_dat
                                        org = xsdbool( g-org_flag IS NOT INITIAL ) ) ).
  ENDMETHOD.

  METHOD zif_accx_assignment_writer~fingerprint.
    DATA(text) = ``.
    SELECT agr_name, from_dat, to_dat, col_flag, org_flag FROM agr_users WHERE uname = @user
      ORDER BY agr_name, from_dat, to_dat INTO TABLE @DATA(rows).
    LOOP AT rows INTO DATA(row).
      text = |{ text }A{ row-agr_name }{ row-from_dat }{ row-to_dat }{ row-col_flag }{ row-org_flag };|.
    ENDLOOP.
    SELECT profile FROM ust04 WHERE bname = @user ORDER BY profile INTO TABLE @DATA(profiles).
    LOOP AT profiles INTO DATA(profile).
      text = |{ text }P{ profile-profile };|.
    ENDLOOP.
    TRY.
        cl_abap_message_digest=>calculate_hash_for_char( EXPORTING if_algorithm  = 'SHA256'
                                                                   if_data       = text
                                                         IMPORTING ef_hashstring = DATA(hash) ).
        result = hash.
      CATCH cx_abap_message_digest.
        result = |{ strlen( text ) }|.
    ENDTRY.
  ENDMETHOD.

  METHOD zif_accx_assignment_writer~apply.
    DATA groups TYPE STANDARD TABLE OF bapiagr.
    DATA return TYPE STANDARD TABLE OF bapiret2.

    SELECT SINGLE cccategory FROM t000 WHERE mandt = @sy-mandt INTO @DATA(category).
    IF category = 'P'.
      result-messages = VALUE #( ( |Client { sy-mandt } is a production client - role assignments refused.| ) ).
      RETURN.
    ENDIF.
    IF change-user = sy-uname.
      result-messages = VALUE #( ( `Own role assignments are not changed.` ) ).
      RETURN.
    ENDIF.

    " all direct assignments, the changed role replaced (or left out)
    LOOP AT zif_accx_assignment_writer~get_assignments( change-user ) INTO DATA(assignment).
      IF assignment-role = change-role AND assignment-org = abap_false.
        CONTINUE.
      ENDIF.
      APPEND VALUE #( agr_name = assignment-role from_dat = assignment-valid_from to_dat = assignment-valid_to
                      org_flag = COND #( WHEN assignment-org = abap_true THEN 'X' ) ) TO groups.
    ENDLOOP.
    IF change-action = zif_accx_assignment_writer=>co_action-assign.
      APPEND VALUE #( agr_name = change-role from_dat = change-valid_from to_dat = change-valid_to ) TO groups.
    ENDIF.

    CALL FUNCTION 'BAPI_USER_ACTGROUPS_ASSIGN'
      EXPORTING username       = change-user
      TABLES    activitygroups = groups
                return         = return.
    result-ok = xsdbool( NOT line_exists( return[ type = 'E' ] ) AND NOT line_exists( return[ type = 'A' ] ) ).
    IF result-ok = abap_true.
      CALL FUNCTION 'BAPI_TRANSACTION_COMMIT' EXPORTING wait = 'X'.
    ELSE.
      CALL FUNCTION 'BAPI_TRANSACTION_ROLLBACK'.
    ENDIF.
    LOOP AT return INTO DATA(message).
      APPEND |{ message-type } { message-id }/{ message-number }: { message-message }| TO result-messages.
    ENDLOOP.

    result-after = zif_accx_assignment_writer~get_assignments( change-user ).
    SELECT profile FROM ust04 WHERE bname = @change-user ORDER BY profile INTO TABLE @DATA(profiles).
    result-profiles = VALUE #( FOR p IN profiles ( CONV #( p-profile ) ) ).
  ENDMETHOD.

ENDCLASS.
