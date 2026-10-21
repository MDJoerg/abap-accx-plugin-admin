"! <p class="shorttext synchronized">Access Explorer tool: apply_role_change</p>
"! Write tool of plugin ADMIN (decision E10, stage 3). Two calls: the first
"! plans the change with draft_role_change, refuses what must not be changed
"! (derived and SAP template roles, unknown transactions, catalogs or roles,
"! critical authorizations without accept_critical) and stores the plan; the
"! second executes the stored plan with plan_id and confirm = true, if the role
"! has not changed in between. Execution: PFCG menu API, merge mode, profile
"! generation, or for composite roles the single roles with user comparison
"! (ZIF_ACCX_ROLE_CHANGER); changes of a reference role are passed on to its
"! derived roles. New single roles (create) are created first, empty or as a
"! copy of another single role such as an SAP template role. Then a check of
"! the result.
CLASS zcl_accx_t_apply_role_change DEFINITION PUBLIC FINAL CREATE PUBLIC
  INHERITING FROM zcl_accx_tool_base.

  PUBLIC SECTION.
    CONSTANTS co_name TYPE string VALUE `apply_role_change`.

    CONSTANTS: BEGIN OF co_state,
                 planned  TYPE string VALUE `planned`,
                 executed TYPE string VALUE `executed`,
                 partial  TYPE string VALUE `partial`,
                 failed   TYPE string VALUE `failed`,
               END OF co_state.

    TYPES: BEGIN OF ty_payload,
             role                TYPE string,
             "! the role is created (empty, or as a copy of copy_from)
             create              TYPE abap_bool,
             copy_from           TYPE string,
             description         TYPE string,
             "! planned, executed, partial (profile not generated), failed
             state               TYPE string,
             plan_id             TYPE string,
             expires_at          TYPE string,
             reason              TYPE string,
             add_transactions    TYPE string_table,
             remove_transactions TYPE string_table,
             add_catalogs        TYPE string_table,
             remove_catalogs     TYPE string_table,
             "! composite role: single roles to add or remove
             add_roles           TYPE string_table,
             remove_roles        TYPE string_table,
             "! manual values as OBJECT FIELD=VALUE
             manual_values       TYPE string_table,
             "! values for open fields as OBJECT-FIELD=VALUE
             open_values         TYPE string_table,
             "! start authorizations that leave the role with removed catalogs, as OBJECT FIELD=VALUE
             removed_values      TYPE string_table,
             "! entries left out of the plan with the reason
             skipped             TYPE string_table,
             "! critical authorizations and combinations the role gains
             critical_added      TYPE string_table,
             "! composite role: critical authorizations and combinations it no longer grants
             critical_removed    TYPE string_table,
             "! open fields the role has before the change
             open_fields_before  TYPE string_table,
             "! open fields the planned transactions, catalogs and values bring
             open_fields_new     TYPE string_table,
             assigned_users      TYPE i,
             composite_roles     TYPE string_table,
             "! reference role: derived roles the change is passed on to (their organizational levels are kept)
             derived_roles       TYPE string_table,
             transport           TYPE string,
             "! execution
             steps               TYPE zif_accx_role_changer=>ty_steps,
             generated           TYPE abap_bool,
             "! open fields after the execution (profile not generated while any is left)
             open_fields         TYPE string_table,
             "! checks of the result against the plan
             verification        TYPE string_table,
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

    "! OBJECT-FIELD=VALUE entries as values; raises invalid for malformed entries
    METHODS parse_open_values
      IMPORTING !entries      TYPE string_table
      RETURNING VALUE(result) TYPE zif_accx_role_changer=>ty_values
      RAISING   zcx_accx_error.

    "! Start authorizations (S_TCODE, S_SERVICE, S_START) of the nodes below the catalogs
    "! that no other entry of the role menu brings
    METHODS removed_start_values
      IMPORTING !role         TYPE agr_name
                !catalogs     TYPE zif_accx_role_changer=>ty_catalogs
      RETURNING VALUE(result) TYPE zif_accx_role_changer=>ty_values.

    "! Compares the role with the executed change
    METHODS verify
      IMPORTING !change       TYPE zif_accx_role_changer=>ty_change
                !removed      TYPE zif_accx_role_changer=>ty_values OPTIONAL
                !derived      TYPE string_table OPTIONAL
      RETURNING VALUE(result) TYPE string_table.

    METHODS prompt
      IMPORTING !payload      TYPE ty_payload
      RETURNING VALUE(result) TYPE string.

ENDCLASS.

CLASS zcl_accx_t_apply_role_change IMPLEMENTATION.

  METHOD zif_accx_tool~get_descriptor.
    result = VALUE #(
      name        = co_name
      title       = `Apply role change`
      description = |Changes a PFCG role - WRITES TO THE SYSTEM. Two calls: (1) without plan_id it plans the change | &&
                    |(single role: add or remove menu transactions, add launchpad catalogs with their authorization defaults or | &&
                    |remove catalogs with the nodes below them, manual values of one object, values for open fields; composite | &&
                    |role: add or remove single roles, with the user comparison), shows what the | &&
                    |role would gain or lose - including critical authorizations, which are refused unless accept_critical is | &&
                    |set - and returns a plan_id; (2) only after | &&
                    |the user has approved exactly this plan, call again with plan_id and confirm = true. The plan expires | &&
                    |after { zif_accx_plan_store=>co_default_ttl } minutes and is refused if the role changed meanwhile. | &&
                    |Execution works like PFCG: menu change, merge of the proposals (expert mode), manual values, profile | &&
                    |generation; open fields block the generation and are reported - fill them with open_values in a new | &&
                    |plan. Changes of a reference role are passed on to its derived roles (authorization data with | &&
                    |their own organizational levels, profiles, user comparison). With create = true it creates a new | &&
                    |single role in the customer namespace first - empty or as a copy of copy_from (without users), e.g. | &&
                    |of an SAP template role - and applies the other changes to it; everything critical the new role grants | &&
                    |needs accept_critical. Derived roles themselves and SAP template roles are refused. Use | &&
                    |draft_role_change to explore options first.|
      group       = zif_accx_types=>co_group-admin
      read_only   = abap_false
      idempotent  = abap_false
      destructive = abap_true
      sensitivity = zif_accx_types=>co_sensitivity-security
      output_type = `\CLASS=ZCL_ACCX_T_APPLY_ROLE_CHANGE\TYPE=TY_PAYLOAD`
      params      = VALUE #( ( param( name        = `role`
                                      description = |Role to change (planning call): a single role, or a composite role with | &&
                                                    |add_roles/remove_roles; with create = true the name of the new role.|
                                      maximum     = 30 ) )
                             ( param( name        = `create`
                                      kind        = zif_accx_types=>co_kind-boolean
                                      description = |true: create the role as a single role (customer namespace, Z or Y), empty | &&
                                                    |or as a copy of copy_from; nobody holds it afterwards.| ) )
                             ( param( name        = `copy_from`
                                      description = `With create: single role to copy (menu, authorization data, texts; no users), e.g. an SAP template role.`
                                      maximum     = 30 ) )
                             ( param( name        = `description`
                                      description = `With create: description of the new role.`
                                      maximum     = 80 ) )
                             ( param( name        = `add_transactions`
                                      kind        = zif_accx_types=>co_kind-string_list
                                      description = `Transactions to add to the role menu.` ) )
                             ( param( name        = `remove_transactions`
                                      kind        = zif_accx_types=>co_kind-string_list
                                      description = `Transactions to remove from the role menu.` ) )
                             ( param( name        = `add_catalogs`
                                      kind        = zif_accx_types=>co_kind-string_list
                                      description = `Launchpad catalogs to add (with their authorization defaults).` ) )
                             ( param( name        = `remove_catalogs`
                                      kind        = zif_accx_types=>co_kind-string_list
                                      description = `Launchpad catalogs to remove (with the authorization default nodes below them).` ) )
                             ( param( name        = `add_roles`
                                      kind        = zif_accx_types=>co_kind-string_list
                                      description = `Composite role only: single roles to add (its users get them by the user comparison).` ) )
                             ( param( name        = `remove_roles`
                                      kind        = zif_accx_types=>co_kind-string_list
                                      description = `Composite role only: single roles to remove.` ) )
                             ( param( name        = `object`
                                      description = `Authorization object for manual values.`
                                      maximum     = 10 ) )
                             ( param( name        = `values`
                                      kind        = zif_accx_types=>co_kind-string_list
                                      description = `With object: manual values as FIELD=VALUE.` ) )
                             ( param( name        = `open_values`
                                      kind        = zif_accx_types=>co_kind-string_list
                                      description = |Values for open fields as OBJECT-FIELD=VALUE (e.g. S_TABU_NAM-TABLE=T000); | &&
                                                    |filled into every open field of that object and field.| ) )
                             ( param( name        = `transport`
                                      description = `Customizing request to record the role in (if the client records changes).`
                                      maximum     = 20 ) )
                             ( param( name        = `reason`
                                      description = `Why the role is changed (stored with the plan and in the log).` ) )
                             ( param( name        = `accept_critical`
                                      kind        = zif_accx_types=>co_kind-boolean
                                      description = |Allow a plan that adds critical authorizations or combinations (default | &&
                                                    |false; only after the user explicitly accepted them).| ) )
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
    DATA draft_args TYPE REF TO zcl_accx_args_map.
    FIELD-SYMBOLS <draft> TYPE zcl_accx_t_draft_role_change=>ty_payload.

    DATA(role) = to_upper( condense( args->get_string( `role` ) ) ).
    IF role IS INITIAL.
      RAISE EXCEPTION NEW zcx_accx_error( status = zif_accx_types=>co_status-invalid message = `Give the role to change (or plan_id to execute a plan).` ).
    ENDIF.
    IF role CP 'SAP_*'.
      RAISE EXCEPTION NEW zcx_accx_error( status  = zif_accx_types=>co_status-invalid
                                          message = |{ role } is an SAP template role; copy it into the customer namespace and change | &&
                                                    |the copy (role = Z..., create = true, copy_from = { role }).| ).
    ENDIF.
    DATA(role_name) = CONV agr_name( role ).
    DATA(create) = args->get_boolean( name = `create` default = abap_false ).
    DATA(copy_from) = to_upper( condense( args->get_string( `copy_from` ) ) ).
    DATA(description) = condense( args->get_string( `description` ) ).
    DATA(open_values) = parse_open_values( args->get_strings( `open_values` ) ).
    DATA(changer) = zcl_accx_admin_factory=>role_changer( ).
    DATA(transport) = to_upper( condense( args->get_string( `transport` ) ) ).
    DATA(transport_problem) = changer->check_transport( CONV #( transport ) ).
    IF transport_problem IS NOT INITIAL.
      RAISE EXCEPTION NEW zcx_accx_error( status = zif_accx_types=>co_status-invalid message = transport_problem ).
    ENDIF.

    DATA(role_repo) = zcl_accx_domain_factory=>role_repo( ).
    IF create = abap_true.
      IF role_repo->exists( role_name ) = abap_true.
        RAISE EXCEPTION NEW zcx_accx_error( status  = zif_accx_types=>co_status-invalid
                                            message = |Role { role } exists already; plan the change without create.| ).
      ENDIF.
      AUTHORITY-CHECK OBJECT 'S_USER_AGR' ID 'ACT_GROUP' FIELD role_name ID 'ACTVT' FIELD '01'.
      IF sy-subrc <> 0.
        RAISE EXCEPTION NEW zcx_accx_error( status = zif_accx_types=>co_status-denied message = |You may not create role { role } (S_USER_AGR 01).| ).
      ENDIF.
    ELSE.
      IF role_repo->exists( role_name ) = abap_false.
        RAISE EXCEPTION NEW zcx_accx_error( status  = zif_accx_types=>co_status-not_found
                                            message = |Role { role } does not exist; plan it with create = true to create it.| ).
      ENDIF.
      IF ctx->guard( )->can_display_role( role_name ) = abap_false.
        RAISE EXCEPTION NEW zcx_accx_error( status = zif_accx_types=>co_status-denied message = |You may not display role { role }.| ).
      ENDIF.
      AUTHORITY-CHECK OBJECT 'S_USER_AGR' ID 'ACT_GROUP' FIELD role_name ID 'ACTVT' FIELD '02'.
      IF sy-subrc <> 0.
        RAISE EXCEPTION NEW zcx_accx_error( status = zif_accx_types=>co_status-denied message = |You may not change role { role } (S_USER_AGR 02).| ).
      ENDIF.
    ENDIF.
    DATA(info) = COND zif_accx_role_repo=>ty_role_info( WHEN create = abap_false THEN role_repo->get_role_info( role_name ) ).
    IF info-composite = abap_true AND open_values IS NOT INITIAL.
      RAISE EXCEPTION NEW zcx_accx_error( status  = zif_accx_types=>co_status-invalid
                                          message = |{ role } is a composite role and has no authorization data; fill open fields | &&
                                                    |in one of its single roles.| ).
    ENDIF.
    IF info-derived_from IS NOT INITIAL.
      RAISE EXCEPTION NEW zcx_accx_error( status  = zif_accx_types=>co_status-invalid
                                          message = |{ role } is derived from { info-derived_from }; change the reference role | &&
                                                    |{ info-derived_from } - the change is passed on to its derived roles.| ).
    ENDIF.

    DATA(payload) = NEW ty_payload( role            = role
                                    create          = create
                                    copy_from       = copy_from
                                    description     = description
                                    state           = co_state-planned
                                    reason          = condense( args->get_string( `reason` ) )
                                    composite_roles = info-parents
                                    derived_roles   = VALUE #( FOR d IN role_repo->get_derived_roles( role_name ) ( CONV #( d ) ) )
                                    transport       = transport ).
    result-data = payload.
    DATA(change) = VALUE zif_accx_role_changer=>ty_change( role        = role_name
                                                           create      = create
                                                           copy_from   = CONV #( copy_from )
                                                           description = CONV #( description )
                                                           open_values = open_values
                                                           transport   = CONV #( transport ) ).
    payload->open_values = VALUE #( FOR o IN open_values ( |{ o-object }-{ o-field }={ o-low }| ) ).
    " a copy brings the open fields of its source along
    payload->open_fields_before = COND #( WHEN create = abap_false THEN changer->get_open_fields( change-role )
                                          WHEN change-copy_from IS NOT INITIAL THEN changer->get_open_fields( change-copy_from ) ).

    " the draft decides what the change brings
    draft_args = NEW zcl_accx_args_map( ).
    draft_args->set( name = `role` value = role ).
    draft_args->set( name = `create` value = create ).
    draft_args->set( name = `copy_from` value = copy_from ).
    draft_args->set( name = `description` value = description ).
    draft_args->set_list( name = `add_transactions` values = args->get_strings( `add_transactions` ) ).
    draft_args->set_list( name = `remove_transactions` values = args->get_strings( `remove_transactions` ) ).
    draft_args->set_list( name = `add_catalogs` values = args->get_strings( `add_catalogs` ) ).
    draft_args->set_list( name = `remove_catalogs` values = args->get_strings( `remove_catalogs` ) ).
    draft_args->set_list( name = `add_roles` values = args->get_strings( `add_roles` ) ).
    draft_args->set_list( name = `remove_roles` values = args->get_strings( `remove_roles` ) ).
    draft_args->set( name = `object` value = args->get_string( `object` ) ).
    draft_args->set_list( name = `values` values = args->get_strings( `values` ) ).
    DATA(has_menu_or_values) = xsdbool( args->get_strings( `add_transactions` ) IS NOT INITIAL
                                        OR args->get_strings( `remove_transactions` ) IS NOT INITIAL
                                        OR args->get_strings( `add_catalogs` ) IS NOT INITIAL
                                        OR args->get_strings( `remove_catalogs` ) IS NOT INITIAL
                                        OR args->get_strings( `add_roles` ) IS NOT INITIAL
                                        OR args->get_strings( `remove_roles` ) IS NOT INITIAL
                                        OR args->get_string( `object` ) IS NOT INITIAL
                                        OR ( create = abap_true AND copy_from IS NOT INITIAL ) ).
    IF has_menu_or_values = abap_false AND open_values IS INITIAL.
      RAISE EXCEPTION NEW zcx_accx_error(
        status  = zif_accx_types=>co_status-invalid
        message = |Give add_transactions, remove_transactions, add_catalogs, remove_catalogs, object with values or | &&
                  |open_values (single role), add_roles, remove_roles (composite role), or create = true with copy_from or | &&
                  |menu entries (new role).| ).
    ENDIF.
    " the draft checks the name of a new role and its copy source
    IF has_menu_or_values = abap_true OR create = abap_true.
      DATA(draft) = NEW zcl_accx_t_draft_role_change( )->zif_accx_tool~execute( args = draft_args ctx = ctx ).
      ASSIGN draft-data->* TO <draft>.
      payload->assigned_users = <draft>-assigned_users.
      LOOP AT <draft>-transactions INTO DATA(transaction).
        CASE transaction-status.
          WHEN zcl_accx_t_draft_role_change=>co_status-add.
            APPEND transaction-transaction TO change-add_tcodes.
          WHEN zcl_accx_t_draft_role_change=>co_status-remove.
            APPEND transaction-transaction TO change-remove_tcodes.
          WHEN zcl_accx_t_draft_role_change=>co_status-unknown.
            RAISE EXCEPTION NEW zcx_accx_error( status  = zif_accx_types=>co_status-not_found
                                                message = |Transaction { transaction-transaction } does not exist.| ).
          WHEN OTHERS.
            APPEND |{ transaction-transaction }: { transaction-note }| TO payload->skipped.
        ENDCASE.
      ENDLOOP.
      LOOP AT <draft>-catalogs INTO DATA(catalog).
        CASE catalog-status.
          WHEN zcl_accx_t_draft_role_change=>co_status-add.
            APPEND VALUE #( id = catalog-catalog title = catalog-title ) TO change-add_catalogs.
          WHEN zcl_accx_t_draft_role_change=>co_status-remove.
            APPEND VALUE #( id = catalog-catalog title = catalog-title ) TO change-remove_catalogs.
          WHEN zcl_accx_t_draft_role_change=>co_status-unknown.
            RAISE EXCEPTION NEW zcx_accx_error( status = zif_accx_types=>co_status-not_found message = |Catalog { catalog-catalog }: { catalog-note }.| ).
          WHEN OTHERS.
            APPEND |{ catalog-catalog }: { catalog-note }| TO payload->skipped.
        ENDCASE.
      ENDLOOP.
      LOOP AT <draft>-roles INTO DATA(single).
        CASE single-status.
          WHEN zcl_accx_t_draft_role_change=>co_status-add.
            APPEND single-role TO change-add_roles.
          WHEN zcl_accx_t_draft_role_change=>co_status-remove.
            APPEND single-role TO change-remove_roles.
          WHEN zcl_accx_t_draft_role_change=>co_status-unknown.
            RAISE EXCEPTION NEW zcx_accx_error( status = zif_accx_types=>co_status-not_found message = |Role { single-role }: { single-note }.| ).
          WHEN zcl_accx_t_draft_role_change=>co_status-composite.
            RAISE EXCEPTION NEW zcx_accx_error( status = zif_accx_types=>co_status-invalid message = |Role { single-role }: { single-note }.| ).
          WHEN OTHERS.
            APPEND |{ single-role }: { single-note }| TO payload->skipped.
        ENDCASE.
      ENDLOOP.
      LOOP AT <draft>-authorization_values INTO DATA(value).
        IF value-source = `manual` AND value-value IS NOT INITIAL.
          APPEND VALUE #( object = value-object field = value-field low = value-value ) TO change-values.
          APPEND |{ value-object } { value-field }={ value-value }| TO payload->manual_values.
        ENDIF.
        IF value-status = zcl_accx_t_draft_role_change=>co_status-remove.
          APPEND |{ value-object } { value-field }={ value-value }| TO payload->removed_values.
        ENDIF.
        IF value-status = zcl_accx_t_draft_role_change=>co_status-open AND value-field IS NOT INITIAL
           AND NOT line_exists( payload->open_fields_new[ table_line = |{ value-object }-{ value-field }| ] ).
          APPEND |{ value-object }-{ value-field }| TO payload->open_fields_new.
        ENDIF.
      ENDLOOP.
      payload->critical_added = VALUE #( FOR hit IN <draft>-critical_added ( |{ hit-rule } ({ hit-level }): { hit-text }| ) ).
      payload->critical_removed = VALUE #( FOR lost IN <draft>-critical_removed ( |{ lost-rule } ({ lost-level }): { lost-text }| ) ).
      IF change-add_tcodes IS INITIAL AND change-remove_tcodes IS INITIAL AND change-add_catalogs IS INITIAL
         AND change-remove_catalogs IS INITIAL AND change-values IS INITIAL AND open_values IS INITIAL
         AND change-add_roles IS INITIAL AND change-remove_roles IS INITIAL AND change-create = abap_false.
        RAISE EXCEPTION NEW zcx_accx_error( status  = zif_accx_types=>co_status-invalid
                                            message = |Nothing to change in { role }: { concat_lines_of( table = payload->skipped sep = `; ` ) }.| ).
      ENDIF.
    ENDIF.

    " values for open fields: critical rules met with the filled values that are not met today
    IF open_values IS NOT INITIAL.
      DATA(rules) = zcl_accx_domain_factory=>critical_rules( ).
      DATA(before) = role_repo->get_authorization_values( role_name ).
      DATA(after) = before.
      LOOP AT after ASSIGNING FIELD-SYMBOL(<value>) WHERE low IS INITIAL AND high IS INITIAL.
        READ TABLE open_values INTO DATA(open_value) WITH KEY object = <value>-object field = <value>-field.
        IF sy-subrc = 0.
          <value>-low  = open_value-low.
          <value>-high = open_value-high.
        ENDIF.
      ENDLOOP.
      DATA(hits_before) = rules->evaluate( before ).
      APPEND LINES OF rules->evaluate_combinations( hits_before ) TO hits_before.
      IF create = abap_true.
        " a new role gains everything it grants
        CLEAR hits_before.
      ENDIF.
      DATA(hits_after) = rules->evaluate( after ).
      APPEND LINES OF rules->evaluate_combinations( hits_after ) TO hits_after.
      LOOP AT hits_after INTO DATA(hit_after).
        DATA(text) = |{ hit_after-rule } ({ hit_after-level }): { hit_after-text }|.
        IF NOT line_exists( hits_before[ rule = hit_after-rule ] ) AND NOT line_exists( payload->critical_added[ table_line = text ] ).
          APPEND text TO payload->critical_added.
        ENDIF.
      ENDLOOP.
    ENDIF.

    IF payload->critical_added IS NOT INITIAL AND args->get_boolean( name = `accept_critical` default = abap_false ) = abap_false.
      RAISE EXCEPTION NEW zcx_accx_error(
        status  = zif_accx_types=>co_status-denied
        message = |The change would add critical authorizations to { role }: { concat_lines_of( table = payload->critical_added sep = `; ` ) }. | &&
                  |Plan again with accept_critical = true only if the user explicitly accepts them.| ).
    ENDIF.
    payload->add_transactions    = change-add_tcodes.
    payload->remove_transactions = change-remove_tcodes.
    payload->add_catalogs        = VALUE #( FOR c IN change-add_catalogs ( c-id ) ).
    payload->remove_catalogs     = VALUE #( FOR r IN change-remove_catalogs ( r-id ) ).
    payload->add_roles           = change-add_roles.
    payload->remove_roles        = change-remove_roles.

    DATA(plan) = zcl_accx_factory=>plan_store( )->create( VALUE #( tool_name   = co_name
                                                                   caller      = ctx->caller( )
                                                                   profile     = ctx->profile( )
                                                                   target      = role
                                                                   fingerprint = changer->fingerprint( role   = change-role
                                                                                                       source = change-copy_from )
                                                                   payload     = /ui2/cl_json=>serialize( data = change )
                                                                   summary     = prompt( payload->* ) ) ).
    payload->plan_id    = plan-plan_id.
    payload->expires_at = |{ CONV timestamp( plan-expires_at ) TIMESTAMP = ISO TIMEZONE = 'UTC' }| ##TYPE.
    result-status = zif_accx_types=>co_status-confirm.
    result-confirmation = VALUE #( plan_id = plan-plan_id prompt = prompt( payload->* ) expires_at = payload->expires_at ).
    result-sources = VALUE #( ( `draft_role_change (SU24, catalogs, critical authorizations)` ) ( `ZACCX_PLAN (stored plan)` ) ).
    APPEND |Show the plan to the user. Only after the user approved it: call apply_role_change with plan_id = { plan-plan_id } | &&
           |and confirm = true (valid until { payload->expires_at } UTC).| TO result-next_steps.
  ENDMETHOD.

  METHOD execute_plan.
    DATA change TYPE zif_accx_role_changer=>ty_change.

    DATA(store) = zcl_accx_factory=>plan_store( ).
    DATA(plan) = store->claim( plan_id = plan_id tool_name = co_name caller = ctx->caller( ) ).
    /ui2/cl_json=>deserialize( EXPORTING json = plan-payload CHANGING data = change ).
    DATA(changer) = zcl_accx_admin_factory=>role_changer( ).
    DATA(payload) = NEW ty_payload( role                = change-role
                                    create              = change-create
                                    copy_from           = change-copy_from
                                    description         = change-description
                                    plan_id             = plan_id
                                    add_transactions    = change-add_tcodes
                                    remove_transactions = change-remove_tcodes
                                    add_catalogs        = VALUE #( FOR c IN change-add_catalogs ( c-id ) )
                                    remove_catalogs     = VALUE #( FOR r IN change-remove_catalogs ( r-id ) )
                                    add_roles           = change-add_roles
                                    remove_roles        = change-remove_roles
                                    manual_values       = VALUE #( FOR v IN change-values ( |{ v-object } { v-field }={ v-low }| ) )
                                    open_values         = VALUE #( FOR o IN change-open_values ( |{ o-object }-{ o-field }={ o-low }| ) )
                                    transport           = change-transport ).
    result-data = payload.
    IF change-add_roles IS NOT INITIAL OR change-remove_roles IS NOT INITIAL.
      result-sources = VALUE #( ( `ZACCX_PLAN (stored plan)` )
                                ( `PRGN_RFC_ADD_AGRS_TO_COLL_AGR, PRGN_RFC_DEL_AGRS_IN_COLL_AGR (single roles, user comparison)` )
                                ( `AGR_AGRS, AGR_USERS (check)` ) ).
    ELSE.
      result-sources = VALUE #( ( `ZACCX_PLAN (stored plan)` ) ( `CL_PFCG_MENU_MODIFY (role menu)` )
                                ( `PRGN_AUTO_GENERATE_PROFILE_NEW (merge, profile generation)` ) ( `AGR_TCODES, AGR_BUFFI, AGR_1251 (check)` ) ).
    ENDIF.

    IF change-create = abap_true.
      INSERT COND string( WHEN change-copy_from IS INITIAL THEN `PRGN_RFC_CREATE_AGR_MULTIPLE (new role)`
                     ELSE `PRGN_COPY_AGR (copy without users), PRGN_RFC_CHANGE_TEXTS (description)` ) INTO result-sources INDEX 2.
    ENDIF.
    IF changer->fingerprint( role = change-role source = change-copy_from ) <> plan-fingerprint.
      store->close( plan_id = plan_id state = zif_accx_plan_store=>co_state-cancelled outcome = `role changed since planning` ).
      RAISE EXCEPTION NEW zcx_accx_error( status  = zif_accx_types=>co_status-invalid
                                          message = |Role { change-role }| &&
                                                    |{ COND #( WHEN change-create = abap_true THEN | (to be created)| ) }| &&
                                                    |{ COND #( WHEN change-copy_from IS NOT INITIAL THEN | or its copy source { change-copy_from }| ) } | &&
                                                    |was changed after plan { plan_id } was made; nothing was changed. Make a new plan.| ).
    ENDIF.

    " start authorizations the removed catalogs take along, read before their nodes are gone
    DATA(removed) = COND #( WHEN change-remove_catalogs IS NOT INITIAL
                            THEN removed_start_values( role = change-role catalogs = change-remove_catalogs ) ).
    payload->removed_values = VALUE #( FOR x IN removed ( |{ x-object } { x-field }={ x-low }| ) ).

    " the changer commits its steps; the final plan state is committed with the request
    DATA(outcome) = changer->apply( change ).
    payload->steps       = outcome-steps.
    payload->generated   = outcome-generated.
    payload->open_fields = outcome-open.
    payload->transport   = outcome-transport.
    payload->derived_roles = outcome-derived.
    IF outcome-derived IS NOT INITIAL.
      APPEND `SUPRN_TRANSFER_AUTH_DATA (derived roles), AGR_1251, AGR_1016 (check)` TO result-sources.
    ENDIF.
    IF outcome-ok = abap_true.
      payload->verification = verify( change = change removed = removed derived = outcome-derived ).
    ENDIF.
    payload->state = COND #( WHEN outcome-ok = abap_false THEN co_state-failed
                             WHEN outcome-generated = abap_false THEN co_state-partial
                             ELSE co_state-executed ).
    store->close( plan_id = plan_id
                  state   = SWITCH #( payload->state WHEN co_state-failed THEN zif_accx_plan_store=>co_state-failed
                                                     WHEN co_state-partial THEN zif_accx_plan_store=>co_state-partial
                                                     ELSE zif_accx_plan_store=>co_state-executed )
                  outcome = concat_lines_of( sep = `; ` table = VALUE string_table(
                              FOR s IN outcome-steps ( |{ s-step }: { COND #( WHEN s-ok = abap_true THEN `ok` ELSE `failed` ) }| ) ) ) ).

    result-status = SWITCH #( payload->state WHEN co_state-failed THEN zif_accx_types=>co_status-error
                                             WHEN co_state-partial THEN zif_accx_types=>co_status-partial
                                             ELSE zif_accx_types=>co_status-ok ).
    IF payload->state = co_state-partial.
      APPEND |Fill the open fields ({ concat_lines_of( table = outcome-open sep = `, ` ) }) with a new plan: apply_role_change | &&
             |role = { change-role }, open_values = OBJECT-FIELD=VALUE - or maintain them in PFCG and generate the profile. | &&
             |{ COND #( WHEN change-create = abap_true
                        THEN |Nobody holds { change-role } yet; assign it with assign_role once its profile is generated.|
                        ELSE `Until then the users keep the previous authorizations.` ) }| TO result-next_steps.
    ELSEIF payload->state = co_state-executed AND change-create = abap_true.
      APPEND |Nobody holds the new role { change-role } yet: assign it with assign_role (role = { change-role }) to the users | &&
             |who need it, then check with check_user_access.| TO result-next_steps.
    ELSEIF payload->state = co_state-executed AND ( change-add_roles IS NOT INITIAL OR change-remove_roles IS NOT INITIAL ).
      APPEND |The users of { change-role } hold the changed single roles after the user comparison; check with check_user_access.|
        TO result-next_steps.
    ELSEIF payload->state = co_state-executed.
      APPEND |Users holding { change-role }{ COND #( WHEN outcome-derived IS NOT INITIAL
                                                     THEN | or its derived roles { concat_lines_of( table = outcome-derived sep = `, ` ) }| ) } | &&
             |get the new authorizations with their next logon; check with check_user_access.| TO result-next_steps.
    ELSE.
      APPEND |Check the failed step in PFCG (role { change-role }); steps before it may already be saved.| TO result-next_steps.
    ENDIF.
    LOOP AT payload->verification TRANSPORTING NO FIELDS WHERE table_line CP 'derived role *' AND table_line NS ' match the reference role, profile generated: yes'.
      APPEND |A derived role does not match its reference role after passing on; check it in PFCG (Generate derived roles).| TO result-warnings.
      EXIT.
    ENDLOOP.
    LOOP AT payload->verification TRANSPORTING NO FIELDS WHERE table_line CP '*gone: NO'.
      APPEND |Some start authorizations of the removed catalogs are still in the role (the merge keeps maintained or changed | &&
             |authorizations); remove them in PFCG if they are no longer needed.| TO result-warnings.
      EXIT.
    ENDLOOP.
    IF payload->transport IS INITIAL.
      APPEND `The role was not recorded in a request (client settings or no request given); transport it from PFCG if needed.` TO result-warnings.
    ENDIF.
  ENDMETHOD.

  METHOD parse_open_values.
    LOOP AT entries INTO DATA(entry).
      entry = condense( entry ).
      IF entry IS INITIAL.
        CONTINUE.
      ENDIF.
      FIND PCRE `^([A-Za-z0-9_/]+)-([A-Za-z0-9_]+)=(.+)$` IN entry SUBMATCHES DATA(object) DATA(field) DATA(value).
      IF sy-subrc <> 0.
        RAISE EXCEPTION NEW zcx_accx_error( status  = zif_accx_types=>co_status-invalid
                                            message = |open_values entry "{ entry }" is not OBJECT-FIELD=VALUE.| ).
      ENDIF.
      APPEND VALUE #( object = to_upper( object ) field = to_upper( field ) low = condense( value ) ) TO result.
    ENDLOOP.
  ENDMETHOD.

  METHOD verify.
    IF change-create = abap_true.
      SELECT SINGLE @abap_true FROM agr_define WHERE agr_name = @change-role INTO @DATA(created).
      APPEND |role { change-role } created: { COND #( WHEN created = abap_true THEN `yes` ELSE `NO` ) }| TO result.
      IF change-copy_from IS NOT INITIAL.
        " the copy keeps what the merge did not add: values of the source still in the copy
        SELECT DISTINCT object, field, low, high FROM agr_1251 WHERE agr_name = @change-copy_from AND deleted = @space
          INTO TABLE @DATA(source_values).
        SELECT DISTINCT object, field, low, high FROM agr_1251 WHERE agr_name = @change-role AND deleted = @space
          INTO TABLE @DATA(copied_values).
        DATA(lost) = REDUCE i( INIT k = 0 FOR c IN source_values
                               NEXT k = COND #( WHEN line_exists( copied_values[ object = c-object field = c-field low = c-low high = c-high ] )
                                                THEN k ELSE k + 1 ) ).
        APPEND |authorization values of { change-copy_from } in the copy: { lines( source_values ) - lost } of { lines( source_values ) }|
          TO result.
      ENDIF.
    ENDIF.
    SELECT tcode FROM agr_tcodes WHERE agr_name = @change-role AND type = 'TR' INTO TABLE @DATA(menu).
    LOOP AT change-add_tcodes INTO DATA(add).
      APPEND |transaction { add } in menu: { COND #( WHEN line_exists( menu[ tcode = add ] ) THEN `yes` ELSE `NO` ) }| TO result.
    ENDLOOP.
    LOOP AT change-remove_tcodes INTO DATA(remove).
      APPEND |transaction { remove } removed: { COND #( WHEN line_exists( menu[ tcode = remove ] ) THEN `NO` ELSE `yes` ) }| TO result.
    ENDLOOP.
    IF change-add_catalogs IS NOT INITIAL OR change-remove_catalogs IS NOT INITIAL.
      DATA(catalogs) = NEW zcl_accx_fiori_repo( )->zif_accx_fiori_repo~get_role_catalogs( VALUE #( ( change-role ) ) ).
      LOOP AT change-add_catalogs INTO DATA(catalog).
        APPEND |catalog { catalog-id } in menu: { COND #( WHEN line_exists( catalogs[ catalog = catalog-id ] ) THEN `yes` ELSE `NO` ) }|
          TO result.
      ENDLOOP.
      LOOP AT change-remove_catalogs INTO DATA(removed_catalog).
        APPEND |catalog { removed_catalog-id } removed: { COND #( WHEN line_exists( catalogs[ catalog = removed_catalog-id ] )
                                                                   THEN `NO` ELSE `yes` ) }| TO result.
      ENDLOOP.
    ENDIF.
    IF change-add_roles IS NOT INITIAL OR change-remove_roles IS NOT INITIAL.
      DATA(children) = zcl_accx_domain_factory=>role_repo( )->get_role_info( change-role )-children.
      LOOP AT change-add_roles INTO DATA(role_added).
        APPEND |single role { role_added } in composite role: { COND #( WHEN line_exists( children[ table_line = role_added ] )
                                                                         THEN `yes` ELSE `NO` ) }| TO result.
      ENDLOOP.
      LOOP AT change-remove_roles INTO DATA(role_removed).
        APPEND |single role { role_removed } removed: { COND #( WHEN line_exists( children[ table_line = role_removed ] )
                                                                 THEN `NO` ELSE `yes` ) }| TO result.
      ENDLOOP.
      " user comparison: users of the composite role who hold the added single roles today
      SELECT DISTINCT uname FROM agr_users
        WHERE agr_name = @change-role AND from_dat <= @sy-datum AND to_dat >= @sy-datum
        INTO TABLE @DATA(holders).
      IF holders IS NOT INITIAL.
        LOOP AT change-add_roles INTO role_added.
          SELECT DISTINCT uname FROM agr_users FOR ALL ENTRIES IN @holders
            WHERE agr_name = @role_added AND uname = @holders-uname AND from_dat <= @sy-datum AND to_dat >= @sy-datum
            INTO TABLE @DATA(reached).
          APPEND |{ role_added } held by { lines( reached ) } of { lines( holders ) } users of the composite role| TO result.
        ENDLOOP.
      ENDIF.
    ENDIF.
    LOOP AT change-values INTO DATA(value).
      SELECT SINGLE @abap_true FROM agr_1251
        WHERE agr_name = @change-role AND object = @value-object AND field = @value-field AND low = @value-low AND deleted = @space
        INTO @DATA(found).
      APPEND |{ value-object } { value-field }={ value-low } active: { COND #( WHEN found = abap_true THEN `yes` ELSE `NO` ) }| TO result.
      CLEAR found.
    ENDLOOP.
    LOOP AT removed INTO DATA(gone).
      SELECT SINGLE @abap_true FROM agr_1251
        WHERE agr_name = @change-role AND object = @gone-object AND field = @gone-field AND low = @gone-low AND deleted = @space
        INTO @DATA(still).
      APPEND |{ gone-object } { gone-field }={ gone-low } gone: { COND #( WHEN still = abap_true THEN `NO` ELSE `yes` ) }| TO result.
      CLEAR still.
    ENDLOOP.
    IF derived IS INITIAL.
      RETURN.
    ENDIF.
    " derived roles: same values as the reference role, except the organizational levels ($ placeholders there)
    SELECT DISTINCT object, field, low, high FROM agr_1251 WHERE agr_name = @change-role AND deleted = @space
      INTO TABLE @DATA(reference).
    DATA(org_fields) = VALUE string_table( FOR r IN reference WHERE ( low CP '$*' ) ( |{ r-object }-{ r-field }| ) ).
    DELETE reference WHERE low CP '$*'.
    LOOP AT derived INTO DATA(derived_role).
      SELECT DISTINCT object, field, low, high FROM agr_1251 WHERE agr_name = @derived_role AND deleted = @space
        INTO TABLE @DATA(inherited).
      DATA(missing) = REDUCE i( INIT n = 0 FOR v IN reference
                                NEXT n = COND #( WHEN line_exists( inherited[ object = v-object field = v-field low = v-low high = v-high ] )
                                                 THEN n ELSE n + 1 ) ).
      DATA(extra) = REDUCE i( INIT m = 0 FOR w IN inherited
                              NEXT m = COND #( WHEN line_exists( reference[ object = w-object field = w-field low = w-low high = w-high ] )
                                                    OR line_exists( org_fields[ table_line = |{ w-object }-{ w-field }| ] )
                                               THEN m ELSE m + 1 ) ).
      SELECT SINGLE generated FROM agr_1016 WHERE agr_name = @derived_role INTO @DATA(derived_generated).
      APPEND |derived role { derived_role }: authorization values { COND #( WHEN missing = 0 AND extra = 0
                                                                          THEN `match the reference role`
                                                                          ELSE |differ ({ missing } missing, { extra } not in the reference role)| ) }| &&
             |, profile generated: { COND #( WHEN derived_generated = abap_true THEN `yes` ELSE `NO` ) }| TO result.
      CLEAR derived_generated.
    ENDLOOP.
  ENDMETHOD.

  METHOD prompt.
    DATA(parts) = VALUE string_table( ).
    IF payload-add_transactions IS NOT INITIAL.
      APPEND |add transactions { concat_lines_of( table = payload-add_transactions sep = `, ` ) }| TO parts.
    ENDIF.
    IF payload-remove_transactions IS NOT INITIAL.
      APPEND |remove transactions { concat_lines_of( table = payload-remove_transactions sep = `, ` ) }| TO parts.
    ENDIF.
    IF payload-add_catalogs IS NOT INITIAL.
      APPEND |add catalogs { concat_lines_of( table = payload-add_catalogs sep = `, ` ) } with their authorization defaults| TO parts.
    ENDIF.
    IF payload-remove_catalogs IS NOT INITIAL.
      APPEND |remove catalogs { concat_lines_of( table = payload-remove_catalogs sep = `, ` ) } with the nodes below them| &&
             |{ COND #( WHEN payload-removed_values IS NOT INITIAL
                        THEN | (the role loses { concat_lines_of( table = payload-removed_values sep = `, ` ) })| ) }| TO parts.
    ENDIF.
    IF payload-add_roles IS NOT INITIAL.
      APPEND |add single roles { concat_lines_of( table = payload-add_roles sep = `, ` ) }| TO parts.
    ENDIF.
    IF payload-remove_roles IS NOT INITIAL.
      APPEND |remove single roles { concat_lines_of( table = payload-remove_roles sep = `, ` ) }| TO parts.
    ENDIF.
    IF payload-manual_values IS NOT INITIAL.
      APPEND |add { concat_lines_of( table = payload-manual_values sep = `, ` ) }| TO parts.
    ENDIF.
    IF payload-open_values IS NOT INITIAL.
      APPEND |fill open fields { concat_lines_of( table = payload-open_values sep = `, ` ) }| TO parts.
    ENDIF.
    IF payload-create = abap_true.
      result = |Create role { payload-role }| &&
               |{ COND #( WHEN payload-copy_from IS NOT INITIAL THEN | as a copy of { payload-copy_from } (without users)| ) }| &&
               |{ COND #( WHEN payload-description IS NOT INITIAL THEN |, description "{ payload-description }"| ) }| &&
               |{ COND #( WHEN parts IS NOT INITIAL THEN |, then: { concat_lines_of( table = parts sep = `; ` ) }| ) }.|.
    ELSE.
      result = |Change role { payload-role } ({ payload-assigned_users } { COND #( WHEN payload-assigned_users = 1 THEN `user` ELSE `users` ) }): | &&
               |{ concat_lines_of( table = parts sep = `; ` ) }.|.
    ENDIF.
    IF payload-critical_added IS NOT INITIAL.
      result = |{ result } Adds CRITICAL authorizations: { concat_lines_of( table = payload-critical_added sep = `; ` ) }.|.
    ENDIF.
    IF payload-critical_removed IS NOT INITIAL.
      result = |{ result } No longer grants: { concat_lines_of( table = payload-critical_removed sep = `; ` ) }.|.
    ENDIF.
    IF payload-derived_roles IS NOT INITIAL.
      result = |{ result } Passed on to the derived roles { concat_lines_of( table = payload-derived_roles sep = `, ` ) } | &&
               |(their organizational levels are kept).|.
    ENDIF.
    IF payload-transport IS NOT INITIAL.
      result = |{ result } Recorded in request { payload-transport }.|.
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
      result-summary = |**Plan { <payload>-plan_id } - nothing has been changed yet.**\n\n{ result-confirmation-prompt }|.
      IF <payload>-skipped IS NOT INITIAL.
        result-summary = |{ result-summary }\n- Left out: { concat_lines_of( table = <payload>-skipped sep = `; ` ) }|.
      ENDIF.
      IF <payload>-composite_roles IS NOT INITIAL.
        result-summary = |{ result-summary }\n- Also reaches the users of composite roles { concat_lines_of( table = <payload>-composite_roles sep = `, ` ) }|.
      ENDIF.
      IF <payload>-open_fields_new IS NOT INITIAL OR <payload>-open_fields_before IS NOT INITIAL.
        DATA(open) = <payload>-open_fields_before.
        LOOP AT <payload>-open_fields_new INTO DATA(new_open).
          IF NOT line_exists( open[ table_line = new_open ] ).
            APPEND new_open TO open.
          ENDIF.
        ENDLOOP.
        result-summary = |{ result-summary }\n- Open fields (the profile is generated only when none is left; the merge may add | &&
                         |further ones): { concat_lines_of( table = open sep = `, ` ) }|.
      ENDIF.
      result-summary = |{ result-summary }\n\nThe plan expires at { <payload>-expires_at } UTC. Execute only after the user approved it.|.
      RETURN.
    ENDIF.

    result-summary = |Role **{ <payload>-role }** - plan { <payload>-plan_id } | &&
                     |{ SWITCH string( <payload>-state WHEN co_state-executed
                                                       THEN COND #( WHEN <payload>-add_roles IS NOT INITIAL OR <payload>-remove_roles IS NOT INITIAL
                                                                    THEN `**executed**`
                                                                    ELSE `**executed**, profile generated` )
                                                       WHEN co_state-partial THEN `**executed, profile NOT generated** (open fields)`
                                                       ELSE `**failed**` ) }| &&
                     |{ COND #( WHEN <payload>-transport IS NOT INITIAL THEN |, request { <payload>-transport }| ) }.|.
    LOOP AT <payload>-steps INTO DATA(step).
      result-summary = |{ result-summary }\n- { step-step }: { COND #( WHEN step-ok = abap_true THEN `ok` ELSE `**failed**` ) }| &&
                       |{ COND #( WHEN step-messages IS NOT INITIAL THEN | ({ concat_lines_of( table = step-messages sep = `; ` ) })| ) }|.
    ENDLOOP.
    IF <payload>-open_fields IS NOT INITIAL.
      result-summary = |{ result-summary }\n\nOpen fields: { concat_lines_of( table = <payload>-open_fields sep = `, ` ) }|.
    ENDIF.
    IF <payload>-verification IS NOT INITIAL.
      result-summary = |{ result-summary }\n\nCheck: { concat_lines_of( table = <payload>-verification sep = `; ` ) }|.
    ENDIF.
  ENDMETHOD.

  METHOD removed_start_values.
    " start authorizations of the nodes below the catalogs that no other menu entry brings
    DATA(nodes) = zcl_accx_domain_factory=>fiori_repo( )->get_role_menu_nodes( role ).
    DATA(kept) = nodes.
    LOOP AT catalogs INTO DATA(catalog).
      DELETE kept WHERE catalog = catalog-id.
    ENDLOOP.
    LOOP AT nodes INTO DATA(node) WHERE catalog IS NOT INITIAL.
      IF NOT line_exists( catalogs[ id = node-catalog ] ) OR line_exists( kept[ type = node-type name = node-name ] ).
        CONTINUE.
      ENDIF.
      DATA(value) = COND zif_accx_role_changer=>ty_value(
        WHEN node-type = `TR` THEN VALUE #( object = 'S_TCODE' field = 'TCD' low = node-name )
        WHEN node-object = 'IWSG' OR node-object = 'IWSV' THEN VALUE #( object = 'S_SERVICE' field = 'SRV_NAME' low = node-name )
        WHEN node-obj_name IS NOT INITIAL THEN VALUE #( object = 'S_START' field = 'AUTHOBJNAM' low = node-obj_name ) ).
      IF value IS NOT INITIAL AND NOT line_exists( result[ object = value-object field = value-field low = value-low ] ).
        APPEND value TO result.
      ENDIF.
    ENDLOOP.
  ENDMETHOD.
ENDCLASS.
