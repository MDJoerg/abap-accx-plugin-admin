"! <p class="shorttext synchronized">Access Explorer: plugin ADMIN (role maintenance)</p>
"! Contributes the write tools of decision E10, stage 3. Inactive until
"! activated; the tools appear only in profiles assigned to the plugin and
"! allowing writing (ZACCX_PROFILE-ALLOW_WRITE), never in production clients.
"! Run with F9 in ADT to activate the plugin for profile bc/access-admin and
"! create that profile (then register it with F9 on ZCL_ACCX_MCP2_SERVER).
CLASS zcl_accx_admin_plugin DEFINITION PUBLIC FINAL CREATE PUBLIC.

  PUBLIC SECTION.
    INTERFACES zif_accx_plugin.
    INTERFACES if_oo_adt_classrun.

    CONSTANTS co_id      TYPE string VALUE `ADMIN`.
    CONSTANTS co_profile TYPE string VALUE `bc/access-admin`.

ENDCLASS.

CLASS zcl_accx_admin_plugin IMPLEMENTATION.

  METHOD zif_accx_plugin~get_info.
    result = VALUE #( id                = co_id
                      title             = `Role maintenance (write tools)`
                      version           = zif_accx_types=>co_release
                      required_core_api = zif_accx_plugin=>co_core_api_version ).
  ENDMETHOD.

  METHOD zif_accx_plugin~check_prerequisites.
    cl_abap_typedescr=>describe_by_name( EXPORTING  p_name      = 'CL_PFCG_MENU_MODIFY'
                                         EXCEPTIONS type_not_found = 1
                                                    OTHERS         = 2 ).
    result = COND #( WHEN sy-subrc = 0 THEN VALUE #( ok = abap_true )
                     ELSE VALUE #( ok = abap_false message = `PFCG menu API CL_PFCG_MENU_MODIFY is not available.` ) ).
  ENDMETHOD.

  METHOD zif_accx_plugin~get_tools.
    result = VALUE #( ( NEW zcl_accx_t_apply_role_change( ) )
                      ( NEW zcl_accx_t_assign_role( ) ) ).
  ENDMETHOD.

  METHOD if_oo_adt_classrun~main.
    DATA(check) = zif_accx_plugin~check_prerequisites( ).
    IF check-ok = abap_false.
      out->write( |Plugin { co_id } not activated: { check-message }| ).
      RETURN.
    ENDIF.
    SELECT SINGLE cccategory FROM t000 WHERE mandt = @sy-mandt INTO @DATA(category).
    IF category = 'P'.
      out->write( |Client { sy-mandt } is a production client; the write tools of plugin { co_id } are not activated.| ).
      RETURN.
    ENDIF.
    DATA(now) = VALUE timestampl( ).
    GET TIME STAMP FIELD now.
    MODIFY zaccx_plugin FROM @( VALUE #( plugin_id    = co_id
                                         class_name   = 'ZCL_ACCX_ADMIN_PLUGIN'
                                         active       = abap_true
                                         priority     = 10
                                         profiles     = co_profile
                                         activated_by = sy-uname
                                         activated_at = now ) ).
    SELECT SINGLE @abap_true FROM zaccx_profile WHERE profile = @co_profile INTO @DATA(exists).
    IF exists = abap_false.
      INSERT zaccx_profile FROM @( VALUE #( profile     = co_profile
                                            description = 'Access Explorer with role maintenance (write tools)'
                                            tool_groups = '*'
                                            allow_write = abap_true ) ).
    ENDIF.
    COMMIT WORK.
    out->write( |Plugin { co_id } { zif_accx_types=>co_release } activated for profile { co_profile }| &&
                |{ COND #( WHEN exists = abap_false THEN ` (profile created with ALLOW_WRITE)` ) }.| ).
    out->write( `Register the profile as MCP endpoint with F9 on ZCL_ACCX_MCP2_SERVER.` ).
  ENDMETHOD.

ENDCLASS.
