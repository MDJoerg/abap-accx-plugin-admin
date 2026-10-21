"! <p class="shorttext synchronized">Access Explorer tool: assign_role</p>
"! Write tool of plugin ADMIN (decision E10, stage 3): assigns a role to a user,
"! changes the validity of a direct assignment or removes it. Two calls like
"! apply_role_change: the plan (refused for own assignments, without
"! S_USER_GRP/S_USER_AGR 22, for assignments through composite roles and -
"! without accept_critical - when the user gains critical authorizations or
"! combinations) and its execution with plan_id and confirm = true, if the
"! user's assignments have not changed meanwhile.
CLASS zcl_accx_t_assign_role DEFINITION PUBLIC FINAL CREATE PUBLIC
  INHERITING FROM zcl_accx_tool_base.

  PUBLIC SECTION.
    CONSTANTS co_name TYPE string VALUE `assign_role`.

    CONSTANTS: BEGIN OF co_kind,
                 new      TYPE string VALUE `new`,
                 validity TYPE string VALUE `validity`,
                 remove   TYPE string VALUE `remove`,
               END OF co_kind.

    CONSTANTS: BEGIN OF co_state,
                 planned  TYPE string VALUE `planned`,
                 executed TYPE string VALUE `executed`,
                 failed   TYPE string VALUE `failed`,
               END OF co_state.

    TYPES: BEGIN OF ty_payload,
             user              TYPE string,
             user_group        TYPE string,
             user_locked       TYPE abap_bool,
             role              TYPE string,
             role_description  TYPE string,
             composite         TYPE abap_bool,
             "! new, validity (existing direct assignment gets new dates) or remove
             kind              TYPE string,
             valid_from        TYPE string,
             valid_to          TYPE string,
             "! direct assignments of the role before the change, as FROM to TO
             previous          TYPE string_table,
             "! the assignment is valid today after the change
             active_after      TYPE abap_bool,
             "! critical authorizations and combinations the user gains through the role
             critical_added    TYPE string_table,
             state             TYPE string,
             plan_id           TYPE string,
             expires_at        TYPE string,
             reason            TYPE string,
             "! execution
             messages          TYPE string_table,
             verification      TYPE string_table,
           END OF ty_payload.

    METHODS zif_accx_tool~get_descriptor REDEFINITION.
    METHODS zif_accx_tool~execute        REDEFINITION.
    METHODS zif_accx_tool~render_summary REDEFINITION.

  PRIVATE SECTION.
    METHODS plan
      IMPORTING !args         TYPE REF TO zif_accx_args
                !ctx          TYPE REF TO zif_accx_context
      RETURNING VALUE(result) TYPE zif_accx_types=>ty_result
      RAISING   zcx_accx_error.

    METHODS execute_plan
      IMPORTING !plan_id      TYPE string
                !ctx          TYPE REF TO zif_accx_context
      RETURNING VALUE(result) TYPE zif_accx_types=>ty_result
      RAISING   zcx_accx_error.

    "! YYYY-MM-DD or YYYYMMDD; initial input = default
    METHODS parse_date
      IMPORTING !text         TYPE string
                !name         TYPE string
                !default      TYPE d
      RETURNING VALUE(result) TYPE d
      RAISING   zcx_accx_error.

    "! Critical rules and combinations met with the role but not by the user's other roles valid today
    METHODS critical_gain
      IMPORTING !role          TYPE agr_name
                !info          TYPE zif_accx_role_repo=>ty_role_info
                !assignments   TYPE zif_accx_user_repo=>ty_role_assignments
      RETURNING VALUE(result)  TYPE string_table.

    METHODS prompt
      IMPORTING !payload      TYPE ty_payload
      RETURNING VALUE(result) TYPE string.

ENDCLASS.

CLASS zcl_accx_t_assign_role IMPLEMENTATION.

  METHOD zif_accx_tool~get_descriptor.
    result = VALUE #(
      name        = co_name
      title       = `Assign role`
      description = |Assigns a role to a user, changes the validity of a direct assignment or removes it - WRITES TO THE | &&
                    |SYSTEM (user master, profile comparison included). Two calls: (1) without plan_id it plans the change, | &&
                    |shows the critical authorizations and combinations the user would gain (refused unless accept_critical | &&
                    |is set) and returns a plan_id; (2) only after the user approved exactly this plan, call again with plan_id | &&
                    |and confirm = true. Own assignments are never changed; assignments through composite roles cannot be | &&
                    |removed here. The plan expires after { zif_accx_plan_store=>co_default_ttl } minutes and is refused if | &&
                    |the user's assignments changed meanwhile. Use explain_missing_access or diagnose_fiori_app_access to | &&
                    |find the role first.|
      group       = zif_accx_types=>co_group-admin
      read_only   = abap_false
      idempotent  = abap_false
      destructive = abap_true
      sensitivity = zif_accx_types=>co_sensitivity-security
      output_type = `\CLASS=ZCL_ACCX_T_ASSIGN_ROLE\TYPE=TY_PAYLOAD`
      params      = VALUE #( ( param( name        = `user`
                                      description = `User whose assignment is changed (planning call).`
                                      maximum     = 12 ) )
                             ( param( name        = `role`
                                      description = `Single or composite role (planning call).`
                                      maximum     = 30 ) )
                             ( param( name        = `action`
                                      description = |assign (default: new assignment, or new validity of the existing direct | &&
                                                    |assignment) or remove.|
                                      enum        = VALUE #( ( `assign` ) ( `remove` ) ) ) )
                             ( param( name        = `valid_from`
                                      description = `Start of validity, YYYY-MM-DD (default today).`
                                      maximum     = 10 ) )
                             ( param( name        = `valid_to`
                                      description = `End of validity, YYYY-MM-DD (default 9999-12-31).`
                                      maximum     = 10 ) )
                             ( param( name        = `reason`
                                      description = `Why the assignment is changed (stored with the plan and in the log).` ) )
                             ( param( name        = `accept_critical`
                                      kind        = zif_accx_types=>co_kind-boolean
                                      description = |Allow a plan by which the user gains critical authorizations or combinations | &&
                                                    |(default false; only after the user explicitly accepted them).| ) )
                             ( param( name        = zif_accx_types=>co_param-plan_id
                                      description = `Execution call: id of the stored plan.`
                                      maximum     = 32 ) )
                             ( param( name        = zif_accx_types=>co_param-confirm
                                      kind        = zif_accx_types=>co_kind-boolean
                                      description = `Execution call: true once the user has approved the plan.` ) ) ) ).
  ENDMETHOD.

  METHOD zif_accx_tool~execute.
    DATA(plan_id) = condense( args->get_string( zif_accx_types=>co_param-plan_id ) ).
    IF plan_id IS INITIAL.
      result = plan( args = args ctx = ctx ).
    ELSE.
      result = execute_plan( plan_id = plan_id ctx = ctx ).
    ENDIF.
  ENDMETHOD.

  METHOD plan.
    DATA(user) = CONV xubname( to_upper( condense( args->get_string( `user` ) ) ) ).
    DATA(role) = CONV agr_name( to_upper( condense( args->get_string( `role` ) ) ) ).
    DATA(action) = to_lower( condense( args->get_string( `action` ) ) ).
    IF action IS INITIAL.
      action = zif_accx_assignment_writer=>co_action-assign.
    ENDIF.
    IF user IS INITIAL OR role IS INITIAL.
      RAISE EXCEPTION NEW zcx_accx_error( status  = zif_accx_types=>co_status-invalid
                                          message = `Give user and role (or plan_id to execute a plan).` ).
    ENDIF.
    DATA(valid_from) = parse_date( text = args->get_string( `valid_from` ) name = `valid_from` default = sy-datum ).
    DATA(valid_to)   = parse_date( text = args->get_string( `valid_to` ) name = `valid_to` default = '99991231' ).
    IF valid_to < valid_from.
      RAISE EXCEPTION NEW zcx_accx_error( status = zif_accx_types=>co_status-invalid message = `valid_to is before valid_from.` ).
    ENDIF.

    DATA(user_repo) = zcl_accx_domain_factory=>user_repo( ).
    DATA(role_repo) = zcl_accx_domain_factory=>role_repo( ).
    IF user_repo->exists( user ) = abap_false.
      RAISE EXCEPTION NEW zcx_accx_error( status = zif_accx_types=>co_status-not_found message = |User { user } does not exist.| ).
    ENDIF.
    IF ctx->guard( )->can_display_user( user ) = abap_false.
      RAISE EXCEPTION NEW zcx_accx_error( status = zif_accx_types=>co_status-denied message = |You may not display user { user }.| ).
    ENDIF.
    IF role_repo->exists( role ) = abap_false.
      RAISE EXCEPTION NEW zcx_accx_error( status = zif_accx_types=>co_status-not_found message = |Role { role } does not exist.| ).
    ENDIF.
    IF ctx->guard( )->can_display_role( role ) = abap_false.
      RAISE EXCEPTION NEW zcx_accx_error( status = zif_accx_types=>co_status-denied message = |You may not display role { role }.| ).
    ENDIF.
    IF user = ctx->caller( ).
      RAISE EXCEPTION NEW zcx_accx_error( status  = zif_accx_types=>co_status-denied
                                          message = `You may not change your own role assignments; ask another administrator.` ).
    ENDIF.

    DATA(master) = user_repo->get_user( user ).
    DATA(user_group) = CONV xuclass( master-user_group ).
    AUTHORITY-CHECK OBJECT 'S_USER_GRP' ID 'CLASS' FIELD user_group ID 'ACTVT' FIELD '22'.
    IF sy-subrc <> 0.
      RAISE EXCEPTION NEW zcx_accx_error( status  = zif_accx_types=>co_status-denied
                                          message = |You may not assign roles to users of group { user_group } (S_USER_GRP 22).| ).
    ENDIF.
    AUTHORITY-CHECK OBJECT 'S_USER_AGR' ID 'ACT_GROUP' FIELD role ID 'ACTVT' FIELD '22'.
    IF sy-subrc <> 0.
      RAISE EXCEPTION NEW zcx_accx_error( status = zif_accx_types=>co_status-denied message = |You may not assign role { role } (S_USER_AGR 22).| ).
    ENDIF.

    DATA(info) = role_repo->get_role_info( role ).
    DATA(assignments) = user_repo->get_role_assignments( user ).
    DATA(payload) = NEW ty_payload( user             = user
                                    user_group       = master-user_group
                                    user_locked      = master-locked
                                    role             = role
                                    role_description = info-description
                                    composite        = info-composite
                                    state            = co_state-planned
                                    reason           = condense( args->get_string( `reason` ) ) ).
    result-data = payload.
    LOOP AT assignments INTO DATA(existing) WHERE role = role AND via_composite = abap_false.
      APPEND |{ existing-valid_from DATE = ISO } to { existing-valid_to DATE = ISO }| TO payload->previous.
    ENDLOOP.
    DATA(direct_active) = xsdbool( line_exists( assignments[ role = role via_composite = abap_false active = abap_true ] ) ).

    IF action = zif_accx_assignment_writer=>co_action-remove.
      IF payload->previous IS INITIAL.
        IF line_exists( assignments[ role = role via_composite = abap_true ] ).
          RAISE EXCEPTION NEW zcx_accx_error( status  = zif_accx_types=>co_status-invalid
                                              message = |{ user } holds { role } only through a composite role; remove or change | &&
                                                        |that assignment instead.| ).
        ENDIF.
        RAISE EXCEPTION NEW zcx_accx_error( status = zif_accx_types=>co_status-not_found message = |{ user } has no assignment of { role }.| ).
      ENDIF.
      payload->kind = co_kind-remove.
    ELSE.
      payload->kind       = COND #( WHEN payload->previous IS INITIAL THEN co_kind-new ELSE co_kind-validity ).
      payload->valid_from = |{ valid_from DATE = ISO }|.
      payload->valid_to   = |{ valid_to DATE = ISO }|.
      IF lines( payload->previous ) = 1 AND payload->previous[ 1 ] = |{ payload->valid_from } to { payload->valid_to }|.
        RAISE EXCEPTION NEW zcx_accx_error( status  = zif_accx_types=>co_status-invalid
                                            message = |{ user } already holds { role } from { payload->valid_from } to { payload->valid_to }.| ).
      ENDIF.
      payload->active_after = xsdbool( valid_from <= sy-datum AND valid_to >= sy-datum ).
      " what the user gains, unless the role is already active and only the dates change
      IF direct_active = abap_false.
        payload->critical_added = critical_gain( role = role info = info assignments = assignments ).
      ENDIF.
      IF payload->critical_added IS NOT INITIAL AND args->get_boolean( name = `accept_critical` default = abap_false ) = abap_false.
        RAISE EXCEPTION NEW zcx_accx_error(
          status  = zif_accx_types=>co_status-denied
          message = |{ user } would gain critical authorizations with { role }: { concat_lines_of( table = payload->critical_added sep = `; ` ) }. | &&
                    |Plan again with accept_critical = true only if the user explicitly accepts them.| ).
      ENDIF.
      IF info-composite = abap_false AND info-generated = abap_false.
        APPEND |{ role } has no generated profile; the assignment brings no authorizations until the profile is generated.| TO result-warnings.
      ENDIF.
      IF role CP 'SAP_*'.
        APPEND |{ role } is an SAP template role; customer copies are usually assigned instead.| TO result-warnings.
      ENDIF.
    ENDIF.
    IF master-locked = abap_true.
      APPEND |{ user } is locked ({ master-lock_reasons }).| TO result-warnings.
    ENDIF.
    SELECT SINGLE @abap_true FROM ust04 AS u
      WHERE u~bname = @user AND NOT EXISTS ( SELECT profile FROM agr_1016 WHERE profile = u~profile )
      INTO @DATA(own_profiles).
    IF own_profiles = abap_true AND payload->kind <> co_kind-remove.
      APPEND |{ user } also holds profiles not generated from roles; the critical check covers roles only.| TO result-warnings.
    ENDIF.

    DATA(change) = VALUE zif_accx_assignment_writer=>ty_change( user = user role = role action = action
                                                                 valid_from = valid_from valid_to = valid_to ).
    DATA(plan) = zcl_accx_factory=>plan_store( )->create(
      VALUE #( tool_name   = co_name
               caller      = ctx->caller( )
               profile     = ctx->profile( )
               target      = |{ user }/{ role }|
               fingerprint = zcl_accx_admin_factory=>assignment_writer( )->fingerprint( user )
               payload     = /ui2/cl_json=>serialize( data = change )
               summary     = prompt( payload->* ) ) ).
    payload->plan_id    = plan-plan_id.
    payload->expires_at = |{ CONV timestamp( plan-expires_at ) TIMESTAMP = ISO TIMEZONE = 'UTC' }| ##TYPE.
    result-status = zif_accx_types=>co_status-confirm.
    result-confirmation = VALUE #( plan_id = plan-plan_id prompt = prompt( payload->* ) expires_at = payload->expires_at ).
    result-sources = VALUE #( ( `USR02, AGR_USERS (user and assignments)` ) ( `AGR_1251, USCRAUTH, USRCOMB (critical authorizations)` )
                              ( `ZACCX_PLAN (stored plan)` ) ).
    APPEND |Show the plan to the user. Only after the user approved it: call assign_role with plan_id = { plan-plan_id } | &&
           |and confirm = true (valid until { payload->expires_at } UTC).| TO result-next_steps.
  ENDMETHOD.

  METHOD execute_plan.
    DATA change TYPE zif_accx_assignment_writer=>ty_change.

    DATA(store) = zcl_accx_factory=>plan_store( ).
    DATA(plan) = store->claim( plan_id = plan_id tool_name = co_name caller = ctx->caller( ) ).
    /ui2/cl_json=>deserialize( EXPORTING json = plan-payload CHANGING data = change ).
    DATA(writer) = zcl_accx_admin_factory=>assignment_writer( ).
    DATA(assign) = xsdbool( change-action = zif_accx_assignment_writer=>co_action-assign ).
    DATA(active) = xsdbool( assign = abap_true AND change-valid_from <= sy-datum AND change-valid_to >= sy-datum ).
    DATA(payload) = NEW ty_payload( user         = change-user
                                    role         = change-role
                                    plan_id      = plan_id
                                    kind         = COND #( WHEN assign = abap_false THEN co_kind-remove ELSE co_kind-new )
                                    valid_from   = COND #( WHEN assign = abap_true THEN |{ change-valid_from DATE = ISO }| )
                                    valid_to     = COND #( WHEN assign = abap_true THEN |{ change-valid_to DATE = ISO }| )
                                    active_after = active ).
    result-data = payload.
    result-sources = VALUE #( ( `ZACCX_PLAN (stored plan)` ) ( `BAPI_USER_ACTGROUPS_ASSIGN (assignment, profile comparison)` )
                              ( `AGR_USERS, UST04 (check)` ) ).

    IF writer->fingerprint( change-user ) <> plan-fingerprint.
      store->close( plan_id = plan_id state = zif_accx_plan_store=>co_state-cancelled outcome = `assignments changed since planning` ).
      RAISE EXCEPTION NEW zcx_accx_error( status  = zif_accx_types=>co_status-invalid
                                          message = |The role assignments of { change-user } changed after plan { plan_id } was made; | &&
                                                    |nothing was changed. Make a new plan.| ).
    ENDIF.

    DATA(outcome) = writer->apply( change ).
    payload->messages = outcome-messages.
    DATA(after) = VALUE #( outcome-after[ role = change-role org = abap_false ] OPTIONAL ).
    IF assign = abap_false.
      APPEND |assignment removed: { COND #( WHEN after IS INITIAL THEN `yes` ELSE `NO` ) }| TO payload->verification.
    ELSE.
      APPEND |assigned { COND #( WHEN after-valid_from = change-valid_from AND after-valid_to = change-valid_to
                                 THEN |from { after-valid_from DATE = ISO } to { after-valid_to DATE = ISO }: yes| ELSE `as planned: NO` ) }|
        TO payload->verification.
    ENDIF.
    " the profile comparison puts the role's profile into the user master only while an assignment is valid
    SELECT SINGLE profile FROM agr_1016 WHERE agr_name = @change-role INTO @DATA(role_profile).
    IF role_profile IS NOT INITIAL AND outcome-ok = abap_true.
      DATA(in_master) = xsdbool( line_exists( outcome-profiles[ table_line = CONV string( role_profile ) ] ) ).
      APPEND |profile { role_profile } { COND #( WHEN active = abap_true THEN `in` ELSE `not in` ) } the user master: | &&
             |{ COND #( WHEN in_master = active THEN `yes` ELSE `NO (another assignment may still bring it)` ) }| TO payload->verification.
    ENDIF.
    payload->state = COND #( WHEN outcome-ok = abap_true THEN co_state-executed ELSE co_state-failed ).
    store->close( plan_id = plan_id
                  state   = COND #( WHEN outcome-ok = abap_true THEN zif_accx_plan_store=>co_state-executed
                                    ELSE zif_accx_plan_store=>co_state-failed )
                  outcome = concat_lines_of( table = outcome-messages sep = `; ` ) ).
    result-status = COND #( WHEN outcome-ok = abap_true THEN zif_accx_types=>co_status-ok ELSE zif_accx_types=>co_status-error ).
    IF outcome-ok = abap_true AND active = abap_true.
      APPEND |{ change-user } gets the authorizations of { change-role } with the next logon; check with check_user_access.|
        TO result-next_steps.
    ELSEIF outcome-ok = abap_true AND assign = abap_true AND change-valid_from > sy-datum.
      APPEND |The assignment starts on { change-valid_from DATE = ISO }; the profile comparison (PFUD) adds the profile then.|
        TO result-next_steps.
    ENDIF.
  ENDMETHOD.

  METHOD parse_date.
    DATA(digits) = replace( val = condense( text ) sub = `-` with = `` occ = 0 ).
    IF digits IS INITIAL.
      result = default.
      RETURN.
    ENDIF.
    IF strlen( digits ) <> 8 OR digits CN '0123456789'.
      RAISE EXCEPTION NEW zcx_accx_error( status = zif_accx_types=>co_status-invalid message = |{ name } "{ text }" is not a date YYYY-MM-DD.| ).
    ENDIF.
    result = digits.
    CALL FUNCTION 'DATE_CHECK_PLAUSIBILITY'
      EXPORTING  date                      = result
      EXCEPTIONS plausibility_check_failed = 1
                 OTHERS                    = 2.
    IF sy-subrc <> 0.
      RAISE EXCEPTION NEW zcx_accx_error( status = zif_accx_types=>co_status-invalid message = |{ name } "{ text }" is not a valid date.| ).
    ENDIF.
  ENDMETHOD.

  METHOD critical_gain.
    DATA before TYPE zif_accx_critical_rules=>ty_auth_values.
    DATA(role_repo) = zcl_accx_domain_factory=>role_repo( ).
    DATA(rules) = zcl_accx_domain_factory=>critical_rules( ).
    DATA(planned_role) = role.

    " the user's roles valid today (composite assignments list their single roles too)
    LOOP AT assignments INTO DATA(assignment) WHERE active = abap_true AND role <> planned_role.
      APPEND LINES OF role_repo->get_authorization_values( assignment-role ) TO before.
    ENDLOOP.
    DATA(after) = before.
    DATA(singles) = COND string_table( WHEN info-composite = abap_true THEN info-children ELSE VALUE #( ( CONV #( planned_role ) ) ) ).
    LOOP AT singles INTO DATA(single).
      APPEND LINES OF role_repo->get_authorization_values( CONV #( single ) ) TO after.
    ENDLOOP.

    DATA(hits_before) = rules->evaluate( before ).
    APPEND LINES OF rules->evaluate_combinations( hits_before ) TO hits_before.
    DATA(hits_after) = rules->evaluate( after ).
    APPEND LINES OF rules->evaluate_combinations( hits_after ) TO hits_after.
    LOOP AT hits_after INTO DATA(hit).
      DATA(text) = |{ hit-rule } ({ hit-level }): { hit-text }|.
      IF NOT line_exists( hits_before[ rule = hit-rule ] ) AND NOT line_exists( result[ table_line = text ] ).
        APPEND text TO result.
      ENDIF.
    ENDLOOP.
  ENDMETHOD.

  METHOD prompt.
    result = SWITCH #( payload-kind
               WHEN co_kind-new
               THEN |Assign role { payload-role } to user { payload-user } from { payload-valid_from } to { payload-valid_to }.|
               WHEN co_kind-validity
               THEN |Change the validity of role { payload-role } for user { payload-user } from { concat_lines_of( table = payload-previous sep = `, ` ) } | &&
                    |to { payload-valid_from } to { payload-valid_to }.|
               ELSE |Remove role { payload-role } from user { payload-user } (assigned { concat_lines_of( table = payload-previous sep = `, ` ) }).| ).
    IF payload-critical_added IS NOT INITIAL.
      result = |{ result } The user gains CRITICAL authorizations: { concat_lines_of( table = payload-critical_added sep = `; ` ) }.|.
    ENDIF.
  ENDMETHOD.

  METHOD zif_accx_tool~render_summary.
    FIELD-SYMBOLS <payload> TYPE ty_payload.
    IF result-data IS NOT BOUND OR result-summary IS NOT INITIAL.
      super->zif_accx_tool~render_summary( EXPORTING ctx = ctx CHANGING result = result ).
      RETURN.
    ENDIF.
    ASSIGN result-data->* TO <payload>.

    IF <payload>-state = co_state-planned.
      result-summary = |**Plan { <payload>-plan_id } - nothing has been changed yet.**\n\n{ result-confirmation-prompt }| &&
                       |\n- User group { <payload>-user_group }{ COND #( WHEN <payload>-user_locked = abap_true THEN `, user locked` ) }| &&
                       |{ COND #( WHEN <payload>-composite = abap_true THEN `\n- Composite role: the user gets all its single roles` ) }| &&
                       |{ COND #( WHEN <payload>-kind <> co_kind-remove AND <payload>-active_after = abap_false
                                  THEN `\n- The assignment is not valid today` ) }| &&
                       |\n\nThe plan expires at { <payload>-expires_at } UTC. Execute only after the user approved it.|.
      RETURN.
    ENDIF.
    result-summary = |Plan { <payload>-plan_id } for user **{ <payload>-user }**, role **{ <payload>-role }**: | &&
                     |{ COND #( WHEN <payload>-state = co_state-executed THEN `**executed**` ELSE `**failed**` ) }.| &&
                     |{ COND #( WHEN <payload>-messages IS NOT INITIAL
                                THEN |\n- { concat_lines_of( table = <payload>-messages sep = |\n- | ) }| ) }| &&
                     |{ COND #( WHEN <payload>-verification IS NOT INITIAL
                                THEN |\n\nCheck: { concat_lines_of( table = <payload>-verification sep = `; ` ) }| ) }|.
  ENDMETHOD.

ENDCLASS.
