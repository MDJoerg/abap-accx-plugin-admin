"! Changer double: fingerprint and open fields configurable, apply records the change
CLASS ltd_changer DEFINITION FINAL FOR TESTING.
  PUBLIC SECTION.
    INTERFACES zif_accx_role_changer.
    DATA fingerprint TYPE string VALUE `F1`.
    DATA open        TYPE string_table.
    DATA outcome     TYPE zif_accx_role_changer=>ty_outcome.
    DATA applied     TYPE STANDARD TABLE OF zif_accx_role_changer=>ty_change WITH EMPTY KEY.
ENDCLASS.

CLASS ltd_changer IMPLEMENTATION.
  METHOD zif_accx_role_changer~fingerprint.
    result = fingerprint.
  ENDMETHOD.
  METHOD zif_accx_role_changer~get_open_fields.
    result = open.
  ENDMETHOD.
  METHOD zif_accx_role_changer~check_transport.
    IF transport = 'BAD'.
      result = `Request BAD does not exist.`.
    ENDIF.
  ENDMETHOD.
  METHOD zif_accx_role_changer~apply.
    APPEND change TO applied.
    result = outcome.
  ENDMETHOD.
ENDCLASS.

"! Plan store double in memory
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

"! ZT_ROLE: single role whose S_TABU_NAM TABLE is open, with S_TCODE SM37 and S_SERVICE H9 from catalog C_OLD;
"! ZT_COMP composite with ZT_ROLE (children changeable for the check after the execution); ZT_DERIV derived
"! from ZT_ROLE
CLASS ltd_role_repo DEFINITION FINAL FOR TESTING.
  PUBLIC SECTION.
    INTERFACES zif_accx_role_repo PARTIALLY IMPLEMENTED.
    CLASS-DATA composite_children TYPE string_table.
ENDCLASS.

CLASS ltd_role_repo IMPLEMENTATION.
  METHOD zif_accx_role_repo~exists.
    result = xsdbool( role CP 'ZT_*' ).
  ENDMETHOD.
  METHOD zif_accx_role_repo~get_role_info.
    result = VALUE #( role         = role
                      composite    = xsdbool( role = 'ZT_COMP' )
                      derived_from = COND #( WHEN role = 'ZT_DERIV' THEN 'ZT_ROLE' )
                      children     = COND #( WHEN role = 'ZT_COMP' THEN composite_children )
                      parents      = COND #( WHEN role = 'ZT_ROLE' THEN VALUE #( ( `ZT_COMP` ) ) )
                      generated    = abap_true ).
  ENDMETHOD.
  METHOD zif_accx_role_repo~get_authorization_values.
    result = VALUE #( ( object = 'S_TABU_NAM' auth = 'A1' field = 'ACTVT' low = '03' )
                      ( object = 'S_TABU_NAM' auth = 'A1' field = 'TABLE' )
                      ( object = 'S_TCODE' auth = 'T1' field = 'TCD' low = 'SM37' )
                      ( object = 'S_SERVICE' auth = 'S1' field = 'SRV_NAME' low = 'H9' ) ).
  ENDMETHOD.
  METHOD zif_accx_role_repo~get_transactions ##NEEDED.
  ENDMETHOD.
  METHOD zif_accx_role_repo~get_derived_roles.
    IF role = 'ZT_ROLE'.
      result = VALUE #( ( 'ZT_DERIV' ) ).
    ENDIF.
  ENDMETHOD.
  METHOD zif_accx_role_repo~count_assigned_users.
    LOOP AT VALUE zif_accx_role_repo=>ty_user_counts( ( role = 'ZT_COMP' users = 3 ) ( role = 'ZT_ROLE' users = 2 ) ) INTO DATA(count).
      IF line_exists( roles[ table_line = count-role ] ).
        INSERT count INTO TABLE result.
      ENDIF.
    ENDLOOP.
  ENDMETHOD.
ENDCLASS.

"! ZT_ROLE has catalog C_OLD (no longer in the launchpad content) with SM37 and gateway service hash H9 below it
CLASS ltd_fiori DEFINITION FINAL FOR TESTING.
  PUBLIC SECTION.
    INTERFACES zif_accx_fiori_repo PARTIALLY IMPLEMENTED.
ENDCLASS.

CLASS ltd_fiori IMPLEMENTATION.
  METHOD zif_accx_fiori_repo~get_catalog ##NEEDED.
  ENDMETHOD.
  METHOD zif_accx_fiori_repo~get_role_catalogs.
    result = VALUE #( ( role = 'ZT_ROLE' catalog = `C_OLD` ) ).
  ENDMETHOD.
  METHOD zif_accx_fiori_repo~get_catalog_roles.
    result = VALUE #( ( role = 'ZT_ROLE' catalog = `C_OLD` ) ).
  ENDMETHOD.
  METHOD zif_accx_fiori_repo~get_role_menu_nodes.
    result = VALUE #( ( node = `5` catalog = `C_OLD` type = `TR` name = `SM37` )
                      ( node = `6` catalog = `C_OLD` type = `HT` name = `H9` object = `IWSG` obj_name = `/Z/S_0001` ) ).
  ENDMETHOD.
ENDCLASS.

CLASS ltd_proposals DEFINITION FINAL FOR TESTING.
  PUBLIC SECTION.
    INTERFACES zif_accx_proposal_source.
ENDCLASS.

CLASS ltd_proposals IMPLEMENTATION.
  METHOD zif_accx_proposal_source~get_for_transaction ##NEEDED.
  ENDMETHOD.
  METHOD zif_accx_proposal_source~get_for_service ##NEEDED.
  ENDMETHOD.
ENDCLASS.

"! Critical rule TAB_ALL: S_TABU_NAM with TABLE = *
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

"! The planning path through draft_role_change for transactions and added catalogs is verified live
"! (it needs the real SU24, PFCG and launchpad data); these tests cover refusals, open values,
"! a catalog removal and execution.
CLASS ltc_apply_role_change DEFINITION FINAL FOR TESTING
  DURATION SHORT RISK LEVEL HARMLESS.

  PRIVATE SECTION.
    DATA cut     TYPE REF TO zif_accx_tool.
    DATA ctx     TYPE REF TO zif_accx_context.
    DATA changer TYPE REF TO ltd_changer.
    DATA store   TYPE REF TO ltd_store.

    METHODS setup.
    METHODS teardown.
    "! Arguments role and open_values, plus one further name/value pair
    METHODS args
      IMPORTING !role         TYPE string
                !open         TYPE string OPTIONAL
                !name         TYPE string OPTIONAL
                !value        TYPE string OPTIONAL
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
    METHODS open_values_planned     FOR TESTING RAISING zcx_accx_error.
    METHODS critical_open_value     FOR TESTING RAISING zcx_accx_error.
    METHODS execute_partial         FOR TESTING RAISING zcx_accx_error.
    METHODS stale_plan_cancelled    FOR TESTING RAISING zcx_accx_error.
    METHODS catalog_removed         FOR TESTING RAISING zcx_accx_error.
    METHODS composite_changed       FOR TESTING RAISING zcx_accx_error.
    METHODS derived_roles_passed_on FOR TESTING RAISING zcx_accx_error.
    METHODS role_created            FOR TESTING RAISING zcx_accx_error.
ENDCLASS.

CLASS ltc_apply_role_change IMPLEMENTATION.

  METHOD setup.
    ltd_role_repo=>composite_children = VALUE #( ( `ZT_ROLE` ) ).
    changer = NEW ltd_changer( ).
    store   = NEW ltd_store( ).
    zcl_accx_admin_factory=>inject( role_changer = changer ).
    zcl_accx_factory=>inject( plan_store = store ).
    zcl_accx_domain_factory=>inject( role_repo       = NEW ltd_role_repo( )
                                     critical_rules  = NEW ltd_rules( )
                                     fiori_repo      = NEW ltd_fiori( )
                                     proposal_source = NEW ltd_proposals( ) ).
    cut = NEW zcl_accx_t_apply_role_change( ).
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
    result->set( name = `role` value = role ).
    IF open IS NOT INITIAL.
      result->set( name = `open_values` value = open ).
    ENDIF.
    IF name IS NOT INITIAL.
      result->set( name = name value = value ).
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
    assert_refused( args = args( role = `SAP_X` open = `A-B=1` )
                    status = zif_accx_types=>co_status-invalid text = `*SAP template role*create = true, copy_from = SAP_X*` ).
    assert_refused( args = args( role = `ZT_ROLE` open = `A-B=1` name = `create` value = `true` )
                    status = zif_accx_types=>co_status-invalid text = `Role ZT_ROLE exists already*` ).
    assert_refused( args = args( role = `XX_NEW` name = `create` value = `true` )
                    status = zif_accx_types=>co_status-invalid text = `Give add_transactions*` ).
    assert_refused( args = args( role = `ZT_COMP` open = `A-B=1` )
                    status = zif_accx_types=>co_status-invalid text = `*composite role and has no authorization data*` ).
    assert_refused( args = args( role = `ZT_COMP` name = `add_roles` value = `XX_NONE` )
                    status = zif_accx_types=>co_status-not_found text = `Role XX_NONE: role does not exist.` ).
    assert_refused( args = args( role = `ZT_DERIV` open = `A-B=1` )
                    status = zif_accx_types=>co_status-invalid text = `*derived from ZT_ROLE; change the reference role ZT_ROLE*` ).
    assert_refused( args = args( role = `ZT_ROLE` open = `bad` )
                    status = zif_accx_types=>co_status-invalid text = `*not OBJECT-FIELD=VALUE*` ).
    assert_refused( args = args( role = `ZT_ROLE` )
                    status = zif_accx_types=>co_status-invalid text = `Give add_transactions*` ).
    assert_refused( args = args( role = `ZT_ROLE` open = `A-B=1` name = `transport` value = `BAD` )
                    status = zif_accx_types=>co_status-invalid text = `Request BAD does not exist.` ).
    assert_refused( args = args( role = `XX_NONE` open = `A-B=1` )
                    status = zif_accx_types=>co_status-not_found text = `*does not exist*` ).
    " a catalog the role menu does not contain leaves nothing to change
    assert_refused( args = args( role = `ZT_ROLE` name = `remove_catalogs` value = `C_NONE` )
                    status = zif_accx_types=>co_status-invalid text = `Nothing to change in ZT_ROLE: C_NONE: the role menu does not contain*` ).
    cl_abap_unit_assert=>assert_initial( store->plans ).
  ENDMETHOD.

  METHOD open_values_planned.
    changer->open = VALUE #( ( `S_TABU_NAM-TABLE` ) ).
    DATA(result) = run( args( role = `zt_role` open = `s_tabu_nam-table=T000` name = `reason` value = `ticket 4711` ) ).
    cl_abap_unit_assert=>assert_equals( exp = zif_accx_types=>co_status-confirm act = result-status ).
    cl_abap_unit_assert=>assert_equals( exp = `P1` act = result-confirmation-plan_id ).
    cl_abap_unit_assert=>assert_char_cp( exp = `Change role ZT_ROLE*fill open fields S_TABU_NAM-TABLE=T000.*` act = result-confirmation-prompt ).
    cl_abap_unit_assert=>assert_char_cp( exp = `*nothing has been changed yet*` act = result-summary ).
    cl_abap_unit_assert=>assert_char_cp( exp = `*plan_id = P1 and confirm = true*` act = result-next_steps[ 1 ] ).
    DATA(plan) = store->plans[ 1 ].
    cl_abap_unit_assert=>assert_equals( exp = `ZT_ROLE` act = plan-target ).
    cl_abap_unit_assert=>assert_equals( exp = `F1` act = plan-fingerprint ).
    cl_abap_unit_assert=>assert_equals( exp = zcl_accx_t_apply_role_change=>co_name act = plan-tool_name ).
    cl_abap_unit_assert=>assert_char_cp( exp = `*"OBJECT":"S_TABU_NAM"*"FIELD":"TABLE"*"LOW":"T000"*` act = plan-payload ).
    cl_abap_unit_assert=>assert_initial( changer->applied ).
  ENDMETHOD.

  METHOD critical_open_value.
    assert_refused( args = args( role = `ZT_ROLE` open = `S_TABU_NAM-TABLE=*` )
                    status = zif_accx_types=>co_status-denied text = `*TAB_ALL (high): All tables*accept_critical*` ).
    DATA(result) = run( args( role = `ZT_ROLE` open = `S_TABU_NAM-TABLE=*` name = `accept_critical` value = `true` ) ).
    cl_abap_unit_assert=>assert_equals( exp = zif_accx_types=>co_status-confirm act = result-status ).
    cl_abap_unit_assert=>assert_char_cp( exp = `*Adds CRITICAL authorizations: TAB_ALL*` act = result-confirmation-prompt ).
  ENDMETHOD.

  METHOD execute_partial.
    run( args( role = `ZT_ROLE` open = `S_TABU_NAM-TABLE=T000` ) ).
    changer->outcome = VALUE #( ok = abap_true generated = abap_false open = VALUE #( ( `S_DEVELOP-ACTVT` ) )
                                steps = VALUE #( ( step = `fill S_TABU_NAM-TABLE with T000` ok = abap_true ) ) ).
    DATA(result) = run( execution_args( ) ).
    cl_abap_unit_assert=>assert_equals( exp = zif_accx_types=>co_status-partial act = result-status ).
    cl_abap_unit_assert=>assert_equals( exp = 1 act = lines( changer->applied ) ).
    cl_abap_unit_assert=>assert_equals( exp = VALUE zif_accx_role_changer=>ty_values( ( object = 'S_TABU_NAM' field = 'TABLE' low = 'T000' ) )
                                        act = changer->applied[ 1 ]-open_values ).
    cl_abap_unit_assert=>assert_equals( exp = zif_accx_plan_store=>co_state-partial act = store->plans[ 1 ]-state ).
    cl_abap_unit_assert=>assert_char_cp( exp = `*NOT generated*` act = result-summary ).
    cl_abap_unit_assert=>assert_char_cp( exp = `Fill the open fields (S_DEVELOP-ACTVT)*` act = result-next_steps[ 1 ] ).
  ENDMETHOD.

  METHOD stale_plan_cancelled.
    run( args( role = `ZT_ROLE` open = `S_TABU_NAM-TABLE=T000` ) ).
    changer->fingerprint = `F2`.
    TRY.
        run( execution_args( ) ).
        cl_abap_unit_assert=>fail( `invalid expected` ).
      CATCH zcx_accx_error INTO DATA(error).
        cl_abap_unit_assert=>assert_char_cp( exp = `*was changed after plan P1*` act = error->get_text( ) ).
    ENDTRY.
    cl_abap_unit_assert=>assert_initial( changer->applied ).
    cl_abap_unit_assert=>assert_equals( exp = zif_accx_plan_store=>co_state-cancelled act = store->plans[ 1 ]-state ).
  ENDMETHOD.

  METHOD catalog_removed.
    DATA(planned) = run( args( role = `ZT_ROLE` name = `remove_catalogs` value = `c_old` ) ).
    cl_abap_unit_assert=>assert_equals( exp = zif_accx_types=>co_status-confirm act = planned-status ).
    cl_abap_unit_assert=>assert_equals(
      exp = `Change role ZT_ROLE (2 users): remove catalogs C_OLD with the nodes below them (the role loses S_TCODE TCD=SM37, S_SERVICE SRV_NAME=H9).` &&
            ` Passed on to the derived roles ZT_DERIV (their organizational levels are kept).`
      act = planned-confirmation-prompt ).
    cl_abap_unit_assert=>assert_char_cp( exp = `*"REMOVE_CATALOGS":[{"ID":"C_OLD"*` act = store->plans[ 1 ]-payload ).

    changer->outcome = VALUE #( ok = abap_true generated = abap_true
                                steps = VALUE #( ( step = `remove catalog C_OLD with 2 authorization default nodes` ok = abap_true ) ) ).
    DATA(result) = run( execution_args( ) ).
    cl_abap_unit_assert=>assert_equals( exp = zif_accx_types=>co_status-ok act = result-status ).
    cl_abap_unit_assert=>assert_equals( exp = `C_OLD` act = changer->applied[ 1 ]-remove_catalogs[ 1 ]-id ).
    cl_abap_unit_assert=>assert_initial( changer->applied[ 1 ]-add_tcodes ).
    cl_abap_unit_assert=>assert_equals( exp = zif_accx_plan_store=>co_state-executed act = store->plans[ 1 ]-state ).
    " ZT_ROLE does not exist in the database: catalog and start authorizations count as gone
    cl_abap_unit_assert=>assert_char_cp( exp = `*catalog C_OLD removed: yes; S_TCODE TCD=SM37 gone: yes; S_SERVICE SRV_NAME=H9 gone: yes*`
                                         act = result-summary ).
  ENDMETHOD.

  METHOD composite_changed.
    DATA(args) = args( role = `zt_comp` name = `add_roles` value = `zt_new` ).
    args->set( name = `remove_roles` value = `ZT_ROLE` ).
    DATA(planned) = run( args ).
    cl_abap_unit_assert=>assert_equals( exp = zif_accx_types=>co_status-confirm act = planned-status ).
    cl_abap_unit_assert=>assert_equals( exp = `Change role ZT_COMP (3 users): add single roles ZT_NEW; remove single roles ZT_ROLE.`
                                        act = planned-confirmation-prompt ).
    cl_abap_unit_assert=>assert_char_cp( exp = `*"ADD_ROLES":["ZT_NEW"],"REMOVE_ROLES":["ZT_ROLE"]*` act = store->plans[ 1 ]-payload ).

    changer->outcome = VALUE #( ok = abap_true generated = abap_true
                                steps = VALUE #( ( step = `remove single roles ZT_ROLE (with user comparison)` ok = abap_true )
                                                 ( step = `add single roles ZT_NEW (with user comparison)` ok = abap_true ) ) ).
    ltd_role_repo=>composite_children = VALUE #( ( `ZT_NEW` ) ).
    DATA(result) = run( execution_args( ) ).
    cl_abap_unit_assert=>assert_equals( exp = zif_accx_types=>co_status-ok act = result-status ).
    cl_abap_unit_assert=>assert_equals( exp = VALUE string_table( ( `ZT_NEW` ) ) act = changer->applied[ 1 ]-add_roles ).
    cl_abap_unit_assert=>assert_equals( exp = VALUE string_table( ( `ZT_ROLE` ) ) act = changer->applied[ 1 ]-remove_roles ).
    cl_abap_unit_assert=>assert_char_cp( exp = `*single role ZT_NEW in composite role: yes; single role ZT_ROLE removed: yes*`
                                         act = result-summary ).
    cl_abap_unit_assert=>assert_char_cp( exp = `*hold the changed single roles after the user comparison*` act = result-next_steps[ 1 ] ).
  ENDMETHOD.

  METHOD derived_roles_passed_on.
    DATA(planned) = run( args( role = `ZT_ROLE` open = `S_TABU_NAM-TABLE=T000` ) ).
    cl_abap_unit_assert=>assert_char_cp( exp = `*Passed on to the derived roles ZT_DERIV (their organizational levels are kept).`
                                         act = planned-confirmation-prompt ).

    changer->outcome = VALUE #( ok = abap_true generated = abap_true derived = VALUE #( ( `ZT_DERIV` ) )
                                steps = VALUE #( ( step = `fill S_TABU_NAM-TABLE with T000` ok = abap_true )
                                                 ( step = `pass on to derived roles ZT_DERIV (authorization data, profiles, user comparison)`
                                                   ok   = abap_true ) ) ).
    DATA(result) = run( execution_args( ) ).
    cl_abap_unit_assert=>assert_equals( exp = zif_accx_types=>co_status-ok act = result-status ).
    cl_abap_unit_assert=>assert_equals( exp = VALUE string_table( ( `ZT_DERIV` ) ) act = CAST zcl_accx_t_apply_role_change=>ty_payload( result-data )->derived_roles ).
    cl_abap_unit_assert=>assert_char_cp( exp = `*- pass on to derived roles ZT_DERIV*: ok*` act = result-summary ).
    " neither role exists in the database: no values to compare, no generated profile
    cl_abap_unit_assert=>assert_char_cp( exp = `*derived role ZT_DERIV: authorization values match the reference role, profile generated: NO*`
                                         act = result-summary ).
    cl_abap_unit_assert=>assert_char_cp( exp = `Users holding ZT_ROLE or its derived roles ZT_DERIV get*` act = result-next_steps[ 1 ] ).
    cl_abap_unit_assert=>assert_char_cp( exp = `A derived role does not match*` act = result-warnings[ 1 ] ).
  ENDMETHOD.

  METHOD role_created.
    DATA(args) = args( role = `zn_new` open = `S_TABU_NAM-TABLE=T000` name = `create` value = `true` ).
    args->set( name = `copy_from` value = `zt_role` ).
    args->set( name = `description` value = `New test role` ).
    DATA(planned) = run( args ).
    cl_abap_unit_assert=>assert_equals( exp = zif_accx_types=>co_status-confirm act = planned-status ).
    cl_abap_unit_assert=>assert_equals(
      exp = `Create role ZN_NEW as a copy of ZT_ROLE (without users), description "New test role", then: fill open fields S_TABU_NAM-TABLE=T000.`
      act = planned-confirmation-prompt ).
    cl_abap_unit_assert=>assert_equals( exp = `ZN_NEW` act = store->plans[ 1 ]-target ).

    changer->outcome = VALUE #( ok = abap_true generated = abap_true
                                steps = VALUE #( ( step = `copy ZT_ROLE to ZN_NEW (without users)` ok = abap_true ) ) ).
    DATA(result) = run( execution_args( ) ).
    cl_abap_unit_assert=>assert_equals( exp = zif_accx_types=>co_status-ok act = result-status ).
    cl_abap_unit_assert=>assert_true( changer->applied[ 1 ]-create ).
    cl_abap_unit_assert=>assert_equals( exp = 'ZT_ROLE' act = changer->applied[ 1 ]-copy_from ).
    cl_abap_unit_assert=>assert_equals( exp = 'New test role' act = changer->applied[ 1 ]-description ).
    " the role is not in the database: the check reports it missing
    cl_abap_unit_assert=>assert_char_cp( exp = `*role ZN_NEW created: NO*` act = result-summary ).
    cl_abap_unit_assert=>assert_char_cp( exp = `Nobody holds the new role ZN_NEW yet: assign it with assign_role*` act = result-next_steps[ 1 ] ).
  ENDMETHOD.

ENDCLASS.
