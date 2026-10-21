"! Writer double: fingerprint configurable, apply records the change and returns the outcome
CLASS ltd_writer DEFINITION FINAL FOR TESTING.
  PUBLIC SECTION.
    INTERFACES zif_accx_assignment_writer.
    DATA fingerprint TYPE string VALUE `F1`.
    DATA outcome     TYPE zif_accx_assignment_writer=>ty_outcome.
    DATA applied     TYPE STANDARD TABLE OF zif_accx_assignment_writer=>ty_change WITH EMPTY KEY.
ENDCLASS.

CLASS ltd_writer IMPLEMENTATION.
  METHOD zif_accx_assignment_writer~get_assignments ##NEEDED.
  ENDMETHOD.
  METHOD zif_accx_assignment_writer~fingerprint.
    result = fingerprint.
  ENDMETHOD.
  METHOD zif_accx_assignment_writer~apply.
    APPEND change TO applied.
    result = outcome.
  ENDMETHOD.
ENDCLASS.

CLASS ltd_store DEFINITION FINAL FOR TESTING.
  PUBLIC SECTION.
    INTERFACES zif_accx_plan_store.
    DATA plans TYPE STANDARD TABLE OF zif_accx_plan_store=>ty_plan WITH EMPTY KEY.
ENDCLASS.

CLASS ltd_store IMPLEMENTATION.
  METHOD zif_accx_plan_store~create.
    result = plan.
    result-plan_id = |P{ lines( plans ) + 1 }|.
    result-state   = zif_accx_plan_store=>co_state-open.
    APPEND result TO plans.
  ENDMETHOD.
  METHOD zif_accx_plan_store~get.
    result = VALUE #( plans[ plan_id = plan_id ] OPTIONAL ).
  ENDMETHOD.
  METHOD zif_accx_plan_store~claim.
    READ TABLE plans ASSIGNING FIELD-SYMBOL(<plan>) WITH KEY plan_id = plan_id.
    IF sy-subrc <> 0 OR <plan>-state <> zif_accx_plan_store=>co_state-open.
      RAISE EXCEPTION NEW zcx_accx_error( status = zif_accx_types=>co_status-invalid message = `not open` ).
    ENDIF.
    <plan>-state = zif_accx_plan_store=>co_state-running.
    result = <plan>.
  ENDMETHOD.
  METHOD zif_accx_plan_store~close.
    READ TABLE plans ASSIGNING FIELD-SYMBOL(<plan>) WITH KEY plan_id = plan_id.
    IF sy-subrc = 0.
      <plan>-state   = state.
      <plan>-outcome = outcome.
    ENDIF.
  ENDMETHOD.
ENDCLASS.

"! ZT_USER holds R_OLD (directly, valid) and R_CHILD (through composite R_COMP)
CLASS ltd_user_repo DEFINITION FINAL FOR TESTING.
  PUBLIC SECTION.
    INTERFACES zif_accx_user_repo PARTIALLY IMPLEMENTED.
ENDCLASS.

CLASS ltd_user_repo IMPLEMENTATION.
  METHOD zif_accx_user_repo~exists.
    result = xsdbool( user = 'ZT_USER' OR user = sy-uname ).
  ENDMETHOD.
  METHOD zif_accx_user_repo~get_user.
    result = VALUE #( user = user user_group = `ZT_GROUP` ).
  ENDMETHOD.
  METHOD zif_accx_user_repo~get_role_assignments.
    IF user = 'ZT_USER'.
      result = VALUE #( ( role = 'R_OLD'   valid_from = '20260101' valid_to = '99991231' active = abap_true )
                        ( role = 'R_COMP'  valid_from = '20260101' valid_to = '99991231' active = abap_true )
                        ( role = 'R_CHILD' valid_from = '20260101' valid_to = '99991231' active = abap_true via_composite = abap_true ) ).
    ENDIF.
  ENDMETHOD.
ENDCLASS.

"! R_CRIT grants S_TABU_NAM TABLE *; R_OLD and R_CHILD grant harmless values
CLASS ltd_role_repo DEFINITION FINAL FOR TESTING.
  PUBLIC SECTION.
    INTERFACES zif_accx_role_repo PARTIALLY IMPLEMENTED.
ENDCLASS.

CLASS ltd_role_repo IMPLEMENTATION.
  METHOD zif_accx_role_repo~exists.
    result = xsdbool( role CP 'R_*' ).
  ENDMETHOD.
  METHOD zif_accx_role_repo~get_role_info.
    result = VALUE #( role = role description = |Role { role }| generated = abap_true composite = xsdbool( role = 'R_COMP' ) ).
  ENDMETHOD.
  METHOD zif_accx_role_repo~get_authorization_values.
    result = SWITCH #( role WHEN 'R_CRIT' THEN VALUE #( ( object = 'S_TABU_NAM' auth = 'C1' field = 'TABLE' low = '*' ) )
                            ELSE VALUE #( ( object = 'S_TCODE' auth = 'T1' field = 'TCD' low = 'SU53' ) ) ).
  ENDMETHOD.
ENDCLASS.

CLASS ltd_rules DEFINITION FINAL FOR TESTING.
  PUBLIC SECTION.
    INTERFACES zif_accx_critical_rules PARTIALLY IMPLEMENTED.
ENDCLASS.

CLASS ltd_rules IMPLEMENTATION.
  METHOD zif_accx_critical_rules~evaluate.
    IF line_exists( values[ object = 'S_TABU_NAM' field = 'TABLE' low = '*' ] ).
      result = VALUE #( ( rule = 'TAB_ALL' level = zif_accx_critical_rules=>co_level-high text = `All tables` ) ).
    ENDIF.
  ENDMETHOD.
  METHOD zif_accx_critical_rules~evaluate_combinations ##NEEDED.
  ENDMETHOD.
ENDCLASS.

CLASS ltd_guard DEFINITION FINAL FOR TESTING.
  PUBLIC SECTION.
    INTERFACES zif_accx_caller_guard.
ENDCLASS.

CLASS ltd_guard IMPLEMENTATION.
  METHOD zif_accx_caller_guard~can_display_user.
    result = abap_true.
  ENDMETHOD.
  METHOD zif_accx_caller_guard~can_display_role.
    result = abap_true.
  ENDMETHOD.
  METHOD zif_accx_caller_guard~can_display_profile.
    result = abap_true.
  ENDMETHOD.
  METHOD zif_accx_caller_guard~can_display_authorization.
    result = abap_true.
  ENDMETHOD.
ENDCLASS.

CLASS ltc_assign_role DEFINITION FINAL FOR TESTING
  DURATION SHORT RISK LEVEL HARMLESS.

  PRIVATE SECTION.
    DATA cut    TYPE REF TO zif_accx_tool.
    DATA ctx    TYPE REF TO zif_accx_context.
    DATA writer TYPE REF TO ltd_writer.
    DATA store  TYPE REF TO ltd_store.

    METHODS setup.
    METHODS teardown.
    METHODS args
      IMPORTING !user         TYPE string DEFAULT `ZT_USER`
                !role         TYPE string
                !name         TYPE string OPTIONAL
                !value        TYPE string OPTIONAL
                !name2        TYPE string OPTIONAL
                !value2       TYPE string OPTIONAL
      RETURNING VALUE(result) TYPE REF TO zcl_accx_args_map.
    METHODS execution_args
      RETURNING VALUE(result) TYPE REF TO zcl_accx_args_map.
    METHODS run
      IMPORTING !args         TYPE REF TO zcl_accx_args_map
      RETURNING VALUE(result) TYPE zif_accx_types=>ty_result
      RAISING   zcx_accx_error.
    METHODS assert_refused
      IMPORTING !args   TYPE REF TO zcl_accx_args_map
                !status TYPE string
                !text   TYPE string.

    METHODS refusals                FOR TESTING.
    METHODS critical_new_assignment FOR TESTING RAISING zcx_accx_error.
    METHODS validity_and_removal    FOR TESTING RAISING zcx_accx_error.
    METHODS execute_assignment      FOR TESTING RAISING zcx_accx_error.
    METHODS stale_plan_cancelled    FOR TESTING RAISING zcx_accx_error.
ENDCLASS.

CLASS ltc_assign_role IMPLEMENTATION.

  METHOD setup.
    writer = NEW ltd_writer( ).
    store  = NEW ltd_store( ).
    zcl_accx_admin_factory=>inject( assignment_writer = writer ).
    zcl_accx_factory=>inject( plan_store = store ).
    zcl_accx_domain_factory=>inject( user_repo      = NEW ltd_user_repo( )
                                     role_repo      = NEW ltd_role_repo( )
                                     critical_rules = NEW ltd_rules( ) ).
    cut = NEW zcl_accx_t_assign_role( ).
    ctx = NEW zcl_accx_context( profile       = `test/admin`
                                max_rows      = 50
                                guard         = NEW ltd_guard( )
                                privacy       = NEW zcl_accx_privacy_none( )
                                write_problem = `` ).
  ENDMETHOD.

  METHOD teardown.
    zcl_accx_admin_factory=>reset( ).
    zcl_accx_factory=>reset( ).
    zcl_accx_domain_factory=>reset( ).
  ENDMETHOD.

  METHOD args.
    result = NEW zcl_accx_args_map( ).
    result->set( name = `user` value = user ).
    result->set( name = `role` value = role ).
    IF name IS NOT INITIAL.
      result->set( name = name value = value ).
    ENDIF.
    IF name2 IS NOT INITIAL.
      result->set( name = name2 value = value2 ).
    ENDIF.
  ENDMETHOD.

  METHOD execution_args.
    result = NEW zcl_accx_args_map( ).
    result->set( name = `plan_id` value = `P1` ).
    result->set( name = `confirm` value = `true` ).
  ENDMETHOD.

  METHOD run.
    result = cut->execute( args = args ctx = ctx ).
    cut->render_summary( EXPORTING ctx = ctx CHANGING result = result ).
  ENDMETHOD.

  METHOD assert_refused.
    TRY.
        run( args ).
        cl_abap_unit_assert=>fail( |{ status } expected| ).
      CATCH zcx_accx_error INTO DATA(error).
        cl_abap_unit_assert=>assert_equals( exp = status act = error->status ).
        cl_abap_unit_assert=>assert_char_cp( exp = text act = error->get_text( ) ).
    ENDTRY.
  ENDMETHOD.

  METHOD refusals.
    assert_refused( args = args( user = CONV #( sy-uname ) role = `R_OLD` )
                    status = zif_accx_types=>co_status-denied text = `*own role assignments*` ).
    assert_refused( args = args( user = `NOBODY` role = `R_OLD` )
                    status = zif_accx_types=>co_status-not_found text = `User NOBODY does not exist.` ).
    assert_refused( args = args( role = `R_NEW` name = `action` value = `remove` )
                    status = zif_accx_types=>co_status-not_found text = `*has no assignment of R_NEW*` ).
    assert_refused( args = args( role = `R_CHILD` name = `action` value = `remove` )
                    status = zif_accx_types=>co_status-invalid text = `*only through a composite role*` ).
    assert_refused( args = args( role = `R_OLD` name = `valid_from` value = `2026-01-01` )
                    status = zif_accx_types=>co_status-invalid text = `*already holds R_OLD from 2026-01-01 to 9999-12-31*` ).
    assert_refused( args = args( role = `R_NEW` name = `valid_to` value = `2026-02-30` )
                    status = zif_accx_types=>co_status-invalid text = `*not a valid date*` ).
    assert_refused( args = args( role = `R_NEW` name = `valid_from` value = `2027-01-01` name2 = `valid_to` value2 = `2026-12-31` )
                    status = zif_accx_types=>co_status-invalid text = `valid_to is before valid_from.` ).
    cl_abap_unit_assert=>assert_initial( store->plans ).
  ENDMETHOD.

  METHOD critical_new_assignment.
    assert_refused( args = args( role = `R_CRIT` )
                    status = zif_accx_types=>co_status-denied text = `ZT_USER would gain critical*TAB_ALL (high): All tables*accept_critical*` ).
    DATA(result) = run( args( role = `r_crit` name = `valid_to` value = `2026-12-31` name2 = `accept_critical` value2 = `true` ) ).
    cl_abap_unit_assert=>assert_equals( exp = zif_accx_types=>co_status-confirm act = result-status ).
    cl_abap_unit_assert=>assert_char_cp( exp = |Assign role R_CRIT to user ZT_USER from { sy-datum DATE = ISO } to 2026-12-31. The user gains CRITICAL*|
                                         act = result-confirmation-prompt ).
    DATA(plan) = store->plans[ 1 ].
    cl_abap_unit_assert=>assert_equals( exp = `ZT_USER/R_CRIT` act = plan-target ).
    cl_abap_unit_assert=>assert_char_cp( exp = `*"ACTION":"assign"*"VALID_TO":"2026-12-31"*` act = plan-payload ).
    cl_abap_unit_assert=>assert_initial( writer->applied ).
  ENDMETHOD.

  METHOD validity_and_removal.
    " the active role only changes its dates: no critical check, kind validity
    DATA(result) = run( args( role = `R_OLD` name = `valid_to` value = `2026-12-31` ) ).
    cl_abap_unit_assert=>assert_char_cp( exp = `Change the validity of role R_OLD for user ZT_USER from 2026-01-01 to 9999-12-31 to *2026-12-31.`
                                         act = result-confirmation-prompt ).
    result = run( args( role = `R_OLD` name = `action` value = `remove` ) ).
    cl_abap_unit_assert=>assert_equals( exp = `Remove role R_OLD from user ZT_USER (assigned 2026-01-01 to 9999-12-31).`
                                        act = result-confirmation-prompt ).
    cl_abap_unit_assert=>assert_equals( exp = 2 act = lines( store->plans ) ).
  ENDMETHOD.

  METHOD execute_assignment.
    run( args( role = `R_NEW` name = `valid_to` value = `2026-12-31` ) ).
    writer->outcome = VALUE #( ok       = abap_true
                               messages = VALUE #( ( `S 01/048: Role assignment to user ZT_USER changed` ) )
                               after    = VALUE #( ( role = 'R_NEW' valid_from = sy-datum valid_to = '20261231' ) ) ).
    DATA(result) = run( execution_args( ) ).
    cl_abap_unit_assert=>assert_equals( exp = zif_accx_types=>co_status-ok act = result-status ).
    cl_abap_unit_assert=>assert_equals( exp = 1 act = lines( writer->applied ) ).
    DATA(applied) = writer->applied[ 1 ].
    cl_abap_unit_assert=>assert_equals( exp = 'R_NEW' act = applied-role ).
    cl_abap_unit_assert=>assert_equals( exp = '20261231' act = applied-valid_to ).
    cl_abap_unit_assert=>assert_equals( exp = zif_accx_plan_store=>co_state-executed act = store->plans[ 1 ]-state ).
    cl_abap_unit_assert=>assert_char_cp( exp = `*executed*Check: assigned from * to 2026-12-31: yes*` act = result-summary ).
    cl_abap_unit_assert=>assert_char_cp( exp = `ZT_USER gets the authorizations of R_NEW*` act = result-next_steps[ 1 ] ).
  ENDMETHOD.

  METHOD stale_plan_cancelled.
    run( args( role = `R_NEW` ) ).
    writer->fingerprint = `F2`.
    TRY.
        run( execution_args( ) ).
        cl_abap_unit_assert=>fail( `invalid expected` ).
      CATCH zcx_accx_error INTO DATA(error).
        cl_abap_unit_assert=>assert_char_cp( exp = `*changed after plan P1*` act = error->get_text( ) ).
    ENDTRY.
    cl_abap_unit_assert=>assert_initial( writer->applied ).
    cl_abap_unit_assert=>assert_equals( exp = zif_accx_plan_store=>co_state-cancelled act = store->plans[ 1 ]-state ).
  ENDMETHOD.

ENDCLASS.
