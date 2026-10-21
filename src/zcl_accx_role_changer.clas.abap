"! <p class="shorttext synchronized">Access Explorer: incremental PFCG role change</p>
"! Steps (verified on A4H 2026-10-21):
"!  0. new roles: PRGN_RFC_CREATE_AGR_MULTIPLE (empty single role) or PRGN_COPY_AGR
"!     (copy without users, HR relationships or distribution; PRGN_RFC_CHANGE_TEXTS
"!     for a description of its own); a copy is merged in step 2 as PFCG demands
"!  1. menu: CL_PFCG_MENU_MODIFY (add transaction, add catalog as application
"!     group with its authorization defaults, delete transaction node), optionally
"!     record the role in a request, save (writes change documents, COMMIT)
"!  2. authorization data: PRGN_AUTO_GENERATE_PROFILE_NEW in mode M (merging
"!     procedure: maintained and manual authorizations are kept, proposals of the
"!     menu merged in) plus the manual values; generates the profile unless fields
"!     stay open (S#/419). Modes X and F rebuild from the proposals.
"!  3. open fields: given values written into the empty field values of active
"!     authorizations (AGR_1251, status maintained, change documents CD1251) -
"!     stability class C, as PFCG maintains them
"!  4. profile generation without merge once no field is open
"!  5. reference roles: SUPRN_TRANSFER_AUTH_DATA passes the authorization data on
"!     to the derived roles (their organizational levels are kept), generates their
"!     profiles and runs the user comparison; derived roles have no menu of their
"!     own - PFCG shows the menu of the reference role
"! Composite roles: single roles removed and added with PRGN_RFC_DEL_AGRS_IN_COLL_AGR
"! and PRGN_RFC_ADD_AGRS_TO_COLL_AGR, which include the user comparison.
CLASS zcl_accx_role_changer DEFINITION PUBLIC CREATE PUBLIC.

  PUBLIC SECTION.
    INTERFACES zif_accx_role_changer.

    CONSTANTS co_catalog_url_type TYPE urltype VALUE 'CAT_PROVIDER'.

  PROTECTED SECTION.
    "! Problem text if the change is not allowed, empty otherwise
    METHODS check_allowed
      IMPORTING !role         TYPE agr_name
                !create       TYPE abap_bool DEFAULT abap_false
      RETURNING VALUE(result) TYPE string.

    "! New single role, empty (PRGN_RFC_CREATE_AGR_MULTIPLE) or as a copy (PRGN_COPY_AGR, no users)
    METHODS create_role
      IMPORTING !change TYPE zif_accx_role_changer=>ty_change
      CHANGING  !result TYPE zif_accx_role_changer=>ty_outcome.

    "! What the fingerprint hashes: menu, single and derived roles, authorization data, profile; N for a missing role
    METHODS fingerprint_text
      IMPORTING !role         TYPE agr_name
      RETURNING VALUE(result) TYPE string.

    METHODS change_menu
      IMPORTING !change TYPE zif_accx_role_changer=>ty_change
      CHANGING  !result TYPE zif_accx_role_changer=>ty_outcome.

    "! Single roles added to or removed from a composite role (PRGN_RFC_ADD_AGRS_TO_COLL_AGR,
    "! PRGN_RFC_DEL_AGRS_IN_COLL_AGR: lock, recording, consistency checks, user comparison)
    METHODS change_composite
      IMPORTING !change TYPE zif_accx_role_changer=>ty_change
      CHANGING  !result TYPE zif_accx_role_changer=>ty_outcome.

    "! Merging procedure (mode M) with the manual values; returns abap_true if the profile was generated
    METHODS merge_authorizations
      IMPORTING !change         TYPE zif_accx_role_changer=>ty_change
      CHANGING  !result         TYPE zif_accx_role_changer=>ty_outcome
      RETURNING VALUE(generated) TYPE abap_bool.

    METHODS fill_open_fields
      IMPORTING !change TYPE zif_accx_role_changer=>ty_change
      CHANGING  !result TYPE zif_accx_role_changer=>ty_outcome.

    "! Authorization data passed on to the derived roles of a reference role (SUPRN_TRANSFER_AUTH_DATA:
    "! organizational levels of the derived roles kept, profiles generated, user comparison)
    METHODS pass_on
      IMPORTING !role      TYPE agr_name
                !generated TYPE abap_bool
      CHANGING  !result    TYPE zif_accx_role_changer=>ty_outcome.

    METHODS generate
      IMPORTING !role           TYPE agr_name
      CHANGING  !result         TYPE zif_accx_role_changer=>ty_outcome
      RETURNING VALUE(generated) TYPE abap_bool.

    METHODS add_step
      IMPORTING !step   TYPE string
                !ok     TYPE abap_bool
                !return TYPE bapirettab OPTIONAL
                !text   TYPE string OPTIONAL
      CHANGING  !result TYPE zif_accx_role_changer=>ty_outcome.

ENDCLASS.

CLASS zcl_accx_role_changer IMPLEMENTATION.

  METHOD zif_accx_role_changer~fingerprint.
    DATA(text) = fingerprint_text( role ).
    IF source IS NOT INITIAL.
      text = |{ text }S;{ fingerprint_text( source ) }|.
    ENDIF.
    TRY.
        cl_abap_message_digest=>calculate_hash_for_char( EXPORTING if_algorithm  = 'SHA256'
                                                                   if_data       = text
                                                         IMPORTING ef_hashstring = DATA(hash) ).
        result = hash.
      CATCH cx_abap_message_digest.
        result = |{ strlen( text ) }|.
    ENDTRY.
  ENDMETHOD.

  METHOD fingerprint_text.
    DATA(text) = ``.
    " a role that does not exist yet (no menu, values or profile either)
    SELECT SINGLE @abap_true FROM agr_define WHERE agr_name = @role INTO @DATA(exists).
    IF exists = abap_false.
      text = `N;`.
    ENDIF.
    SELECT tcode, type FROM agr_tcodes WHERE agr_name = @role ORDER BY tcode, type INTO TABLE @DATA(tcodes).
    LOOP AT tcodes INTO DATA(tcode).
      text = |{ text }T{ tcode-tcode }{ tcode-type };|.
    ENDLOOP.
    SELECT object_id, url FROM agr_buffi WHERE agr_name = @role ORDER BY object_id INTO TABLE @DATA(urls).
    LOOP AT urls INTO DATA(url).
      text = |{ text }U{ url-object_id }{ url-url };|.
    ENDLOOP.
    " single roles of a composite role (none for single roles, so their fingerprint is unchanged)
    SELECT child_agr FROM agr_agrs WHERE agr_name = @role ORDER BY child_agr INTO TABLE @DATA(children).
    LOOP AT children INTO DATA(child).
      text = |{ text }C{ child-child_agr };|.
    ENDLOOP.
    " derived roles of a reference role (they receive its changes)
    SELECT agr_name FROM agr_define WHERE parent_agr = @role ORDER BY agr_name INTO TABLE @DATA(derived).
    LOOP AT derived INTO DATA(derived_role).
      text = |{ text }D{ derived_role-agr_name };|.
    ENDLOOP.
    SELECT auth, object, field, low, high, modified, deleted FROM agr_1251 WHERE agr_name = @role
      ORDER BY object, auth, field, low, high INTO TABLE @DATA(values).
    LOOP AT values INTO DATA(value).
      text = |{ text }V{ value-object }{ value-auth }{ value-field }{ value-low }{ value-high }{ value-modified }{ value-deleted };|.
    ENDLOOP.
    SELECT profile, generated FROM agr_1016 WHERE agr_name = @role ORDER BY profile INTO TABLE @DATA(profiles).
    LOOP AT profiles INTO DATA(profile).
      text = |{ text }P{ profile-profile }{ profile-generated };|.
    ENDLOOP.
    result = text.
  ENDMETHOD.

  METHOD zif_accx_role_changer~get_open_fields.
    SELECT DISTINCT object, field FROM agr_1251
      WHERE agr_name = @role AND deleted = @space AND low = @space AND high = @space
      ORDER BY object, field INTO TABLE @DATA(open).
    result = VALUE #( FOR o IN open ( |{ o-object }-{ o-field }| ) ).
    " organizational levels without value
    SELECT varbl FROM agr_1252 WHERE agr_name = @role AND low = @space AND high = @space ORDER BY varbl INTO TABLE @DATA(levels).
    LOOP AT levels INTO DATA(level).
      APPEND |{ level-varbl }| TO result.
    ENDLOOP.
  ENDMETHOD.

  METHOD zif_accx_role_changer~check_transport.
    IF transport IS INITIAL.
      RETURN.
    ENDIF.
    SELECT SINGLE cccoractiv FROM t000 WHERE mandt = @sy-mandt INTO @DATA(recording).
    IF recording = '2' OR recording = '3'.
      result = |Client { sy-mandt } does not allow transports (SCC4); omit the request.|.
      RETURN.
    ENDIF.
    SELECT SINGLE trfunction, trstatus, as4user FROM e070 WHERE trkorr = @transport INTO @DATA(request).
    IF sy-subrc <> 0.
      result = |Request { transport } does not exist.|.
    ELSEIF request-trstatus <> 'D'.
      result = |Request { transport } is released or locked.|.
    ELSEIF request-trfunction <> 'W'.
      result = |{ transport } is not a customizing request; roles are recorded in customizing requests.|.
    ELSEIF request-as4user <> sy-uname.
      SELECT SINGLE @abap_true FROM e070 WHERE strkorr = @transport AND as4user = @sy-uname INTO @DATA(own_task).
      IF own_task = abap_false.
        result = |Request { transport } belongs to { request-as4user } and has no task of yours.|.
      ENDIF.
    ENDIF.
  ENDMETHOD.

  METHOD zif_accx_role_changer~apply.
    DATA(problem) = check_allowed( role = change-role create = change-create ).
    IF problem IS NOT INITIAL.
      add_step( EXPORTING step = `precondition` ok = abap_false text = problem CHANGING result = result ).
      RETURN.
    ENDIF.
    result-transport = change-transport.

    IF change-create = abap_true.
      create_role( EXPORTING change = change CHANGING result = result ).
      IF line_exists( result-steps[ ok = abap_false ] ).
        RETURN.
      ENDIF.
    ENDIF.

    IF change-add_roles IS NOT INITIAL OR change-remove_roles IS NOT INITIAL.
      " composite role: no menu or authorization data of its own, no profile to generate
      change_composite( EXPORTING change = change CHANGING result = result ).
      result-ok        = xsdbool( NOT line_exists( result-steps[ ok = abap_false ] ) ).
      result-generated = result-ok.
      RETURN.
    ENDIF.

    DATA(menu_changes) = xsdbool( change-add_tcodes IS NOT INITIAL OR change-remove_tcodes IS NOT INITIAL
                                  OR change-add_catalogs IS NOT INITIAL OR change-remove_catalogs IS NOT INITIAL ).
    IF menu_changes = abap_true.
      change_menu( EXPORTING change = change CHANGING result = result ).
      IF line_exists( result-steps[ ok = abap_false ] ).
        RETURN.
      ENDIF.
    ENDIF.

    DATA(generated) = abap_false.
    " a copy is merged like PFCG demands it for copies (proposals of the menu brought up to date)
    IF menu_changes = abap_true OR change-values IS NOT INITIAL OR change-copy_from IS NOT INITIAL.
      generated = merge_authorizations( EXPORTING change = change CHANGING result = result ).
      IF line_exists( result-steps[ ok = abap_false ] ).
        RETURN.
      ENDIF.
    ENDIF.

    IF change-open_values IS NOT INITIAL.
      fill_open_fields( EXPORTING change = change CHANGING result = result ).
      generated = abap_false.
    ENDIF.

    result-open = zif_accx_role_changer~get_open_fields( change-role ).
    IF generated = abap_false AND result-open IS INITIAL.
      generated = generate( EXPORTING role = change-role CHANGING result = result ).
    ENDIF.
    result-generated = generated.
    pass_on( EXPORTING role = change-role generated = generated CHANGING result = result ).
    result-ok = xsdbool( NOT line_exists( result-steps[ ok = abap_false ] ) ).
  ENDMETHOD.

  METHOD pass_on.
    DATA return  TYPE bapirettab.
    DATA request TYPE trkorr.

    SELECT agr_name FROM agr_define WHERE parent_agr = @role ORDER BY agr_name INTO TABLE @DATA(derived).
    IF derived IS INITIAL.
      RETURN.
    ENDIF.
    DATA(names) = VALUE string_table( FOR d IN derived ( CONV #( d-agr_name ) ) ).
    DATA(step) = |pass on to derived roles { concat_lines_of( table = names sep = `, ` ) }|.
    IF generated = abap_false.
      " PFCG passes on only generated authorization data
      add_step( EXPORTING step = step ok = abap_true
                          text = |skipped: the profile of { role } is not generated; the derived roles keep their previous | &&
                                 |authorizations until it is and the change is passed on (PFCG, Generate derived roles)|
                CHANGING  result = result ).
      RETURN.
    ENDIF.

    request = result-transport.
    " no dialog: locks the reference and derived roles, records them if the client demands it,
    " keeps the organizational levels of the derived roles and ends with the user comparison
    CALL FUNCTION 'SUPRN_TRANSFER_AUTH_DATA'
      EXPORTING
        top_activity_group = role
        generate_profiles  = 'X'
        no_dialog          = 'X'
      IMPORTING
        return             = return
      CHANGING
        request            = request.
    COMMIT WORK AND WAIT.
    DATA(failed) = xsdbool( line_exists( return[ type = 'E' ] ) OR line_exists( return[ type = 'A' ] ) ).
    add_step( EXPORTING step   = |{ step } (authorization data, profiles, user comparison)|
                        ok     = xsdbool( failed = abap_false )
                        return = return
              CHANGING  result = result ).
    IF failed = abap_false.
      result-derived = names.
    ENDIF.
    IF result-transport IS INITIAL AND request IS NOT INITIAL.
      result-transport = request.
    ENDIF.
  ENDMETHOD.

  METHOD change_menu.
    TYPES: BEGIN OF ty_catalog_node,
             catalog   TYPE string,
             object_id TYPE agr_hier-object_id,
             children  TYPE i,
           END OF ty_catalog_node.
    DATA catalog_nodes TYPE STANDARD TABLE OF ty_catalog_node WITH EMPTY KEY.

    " catalog nodes to remove; the menu API deletes the authorization default nodes below them too
    IF change-remove_catalogs IS NOT INITIAL.
      SELECT h~object_id, b~url FROM agr_hier AS h
        INNER JOIN agr_buffi AS b ON b~agr_name = h~agr_name AND b~object_id = h~object_id
        WHERE h~agr_name = @change-role AND h~reporttype = 'OT' AND h~report = 'CAT_PROVIDER'
        INTO TABLE @DATA(candidates).
      LOOP AT change-remove_catalogs INTO DATA(removal).
        DATA(prefix) = |X-SAP-UI2-CATALOGPAGE:{ removal-id }|.
        LOOP AT candidates INTO DATA(candidate) WHERE url = prefix OR url CP |{ prefix }?*|.
          SELECT COUNT(*) FROM agr_hier WHERE agr_name = @change-role AND parent_id = @candidate-object_id INTO @DATA(children).
          APPEND VALUE #( catalog = removal-id object_id = candidate-object_id children = children ) TO catalog_nodes.
        ENDLOOP.
        IF sy-subrc <> 0.
          add_step( EXPORTING step = |remove catalog { removal-id }| ok = abap_false text = `catalog node not found in the role menu`
                    CHANGING  result = result ).
          RETURN.
        ENDIF.
      ENDLOOP.
    ENDIF.

    cl_pfcg_menu_modify=>retrieve_for_update( EXPORTING iv_role = change-role IMPORTING er_role = DATA(menu) et_return = DATA(return) ).
    IF menu IS NOT BOUND OR line_exists( return[ type = 'E' ] ) OR line_exists( return[ type = 'A' ] ).
      add_step( EXPORTING step = `open role menu` ok = abap_false return = return CHANGING result = result ).
      RETURN.
    ENDIF.

    LOOP AT catalog_nodes INTO DATA(catalog_node).
      menu->menu_delete_node( EXPORTING iv_object_id = catalog_node-object_id IMPORTING et_return = return ).
      add_step( EXPORTING step   = |remove catalog { catalog_node-catalog } with { catalog_node-children } authorization default | &&
                                   |{ COND #( WHEN catalog_node-children = 1 THEN `node` ELSE `nodes` ) }|
                          ok     = xsdbool( NOT line_exists( return[ type = 'E' ] ) )
                          return = return
                CHANGING  result = result ).
    ENDLOOP.
    menu->menu_get_nodes( IMPORTING et_nodes = DATA(nodes) ).
    LOOP AT change-remove_tcodes INTO DATA(remove).
      LOOP AT nodes INTO DATA(node) WHERE reporttype = 'TR' AND tcode = remove.
        menu->menu_delete_node( EXPORTING iv_object_id = node-object_id IMPORTING et_return = return ).
        add_step( EXPORTING step = |remove transaction { remove }| ok = xsdbool( NOT line_exists( return[ type = 'E' ] ) )
                            return = return
                  CHANGING  result = result ).
      ENDLOOP.
    ENDLOOP.
    LOOP AT change-add_tcodes INTO DATA(add).
      menu->menu_add_transaction( EXPORTING iv_tcode = CONV #( add ) IMPORTING et_return = return ).
      add_step( EXPORTING step = |add transaction { add }| ok = xsdbool( NOT line_exists( return[ type = 'E' ] ) ) return = return
                CHANGING  result = result ).
    ENDLOOP.
    LOOP AT change-add_catalogs INTO DATA(catalog).
      menu->menu_add_application_group(
        EXPORTING iv_url_type  = co_catalog_url_type
                  iv_url       = CONV #( |X-SAP-UI2-CATALOGPAGE:{ catalog-id }?ROLE_ORIGIN={ sy-sysid }CLNT{ sy-mandt }| &&
                                         |&AUTH_DEFAULTS=X&DEST_FES=| )
                  iv_node_text = CONV #( COND string( WHEN catalog-title IS NOT INITIAL THEN catalog-title ELSE catalog-id ) )
        IMPORTING et_return    = return ).
      add_step( EXPORTING step = |add catalog { catalog-id } with authorization defaults| ok = xsdbool( NOT line_exists( return[ type = 'E' ] ) )
                          return = return
                CHANGING  result = result ).
    ENDLOOP.
    IF line_exists( result-steps[ ok = abap_false ] ).
      menu->cancel( ).
      RETURN.
    ENDIF.

    IF change-transport IS NOT INITIAL.
      DATA(request) = change-transport.
      TRY.
          menu->role_add_to_request( IMPORTING ev_rejected = DATA(rejected) et_return = return
                                     CHANGING  cv_request  = request ).
        CATCH cx_pfcg_role_scc4 INTO DATA(scc4).
          rejected = abap_true.
          return = VALUE #( ( type = 'E' message = scc4->get_text( ) ) ).
      ENDTRY.
      add_step( EXPORTING step = |record role in request { request }| ok = xsdbool( rejected = abap_false ) return = return
                CHANGING  result = result ).
      IF rejected = abap_true.
        menu->cancel( ).
        RETURN.
      ENDIF.
      result-transport = request.
    ENDIF.

    " SAVE releases the instance (its attributes can no longer be read)
    cl_pfcg_menu_modify=>save( IMPORTING ev_rejected = rejected et_return = return ).
    add_step( EXPORTING step = `save menu` ok = xsdbool( rejected = abap_false ) return = return CHANGING result = result ).
    IF result-transport IS INITIAL.
      " automatic recording: the request PFCG recorded the role in
      SELECT SINGLE e~trkorr FROM e071 AS o INNER JOIN e070 AS t ON t~trkorr = o~trkorr
                                           INNER JOIN e070 AS e ON e~trkorr = t~strkorr
        WHERE o~pgmid = 'R3TR' AND o~object = 'ACGR' AND o~obj_name = @change-role AND e~trstatus = 'D'
        INTO @result-transport.
    ENDIF.
  ENDMETHOD.

  METHOD merge_authorizations.
    DATA return TYPE STANDARD TABLE OF bapiret2.
    DATA none   TYPE susr_t_sel_opt_object.
    DATA manual TYPE STANDARD TABLE OF tvordata.
    manual = VALUE #( FOR v IN change-values ( object = v-object field = v-field low = v-low high = v-high ) ).

    " mode M = merging procedure (old data kept, proposals of the menu merged in);
    " X and F would rebuild the authorizations from the proposals and lose maintained values
    CALL FUNCTION 'PRGN_AUTO_GENERATE_PROFILE_NEW'
      EXPORTING
        activity_group              = change-role
        no_dialog                   = 'X'
        rebuild_auth_data           = 'M'
        org_levels_with_star        = ' '
        fill_empty_fields_with_star = ' '
        generate_profile            = 'X'
      TABLES
        return                      = return
        manual_auths                = manual
        objcts_excl                 = none
      EXCEPTIONS
        OTHERS                      = 1.
    DATA(subrc) = sy-subrc.
    COMMIT WORK AND WAIT.
    " open fields or organizational levels block the generation only (S#/419), the data is saved
    DATA(open_only) = xsdbool( line_exists( return[ id = 'S#' number = '419' ] ) ).
    DATA(failed) = xsdbool( subrc <> 0 AND open_only = abap_false ).
    add_step( EXPORTING step   = |merge proposals{ COND #( WHEN manual IS NOT INITIAL THEN ` and manual values` ) } (expert mode merge)|
                        ok     = xsdbool( failed = abap_false )
                        return = COND #( WHEN open_only = abap_true THEN VALUE #( ) ELSE return )
              CHANGING  result = result ).
    generated = xsdbool( subrc = 0 ).
  ENDMETHOD.

  METHOD fill_open_fields.
    DATA old_rows TYPE STANDARD TABLE OF cd1251.
    DATA new_rows TYPE STANDARD TABLE OF cd1251.

    LOOP AT change-open_values INTO DATA(value).
      SELECT counter, auth, object, field, low, high FROM agr_1251
        WHERE agr_name = @change-role AND object = @value-object AND field = @value-field
          AND deleted = @space AND low = @space AND high = @space
        INTO TABLE @DATA(rows).
      IF rows IS INITIAL.
        add_step( EXPORTING step = |fill { value-object }-{ value-field }| ok = abap_true
                            text = `no open field - nothing to fill`
                  CHANGING  result = result ).
        CONTINUE.
      ENDIF.
      LOOP AT rows INTO DATA(row).
        UPDATE agr_1251 SET low = @value-low, high = @value-high, modified = 'G'
          WHERE agr_name = @change-role AND counter = @row-counter.
        UPDATE agr_1250 SET modified = 'G'
          WHERE agr_name = @change-role AND object = @row-object AND auth = @row-auth AND modified = 'S'.
        APPEND VALUE #( agr_name = change-role object = row-object auth = row-auth field = row-field counter = row-counter )
          TO old_rows.
        APPEND VALUE #( agr_name = change-role object = row-object auth = row-auth field = row-field counter = row-counter
                        low = value-low high = value-high ) TO new_rows.
      ENDLOOP.
      add_step( EXPORTING step = |fill { value-object }-{ value-field } with { value-low }| &&
                                 |{ COND #( WHEN value-high IS NOT INITIAL THEN | to { value-high }| ) }|
                          ok   = abap_true
                          text = |{ lines( rows ) } { COND #( WHEN lines( rows ) = 1 THEN `authorization` ELSE `authorizations` ) }|
                CHANGING  result = result ).
    ENDLOOP.
    IF new_rows IS NOT INITIAL.
      CALL FUNCTION 'PRGN_CHANGEDOCUMENT_WRITE'
        EXPORTING
          activity_group = change-role
          upd_cd1251     = 'U'
        TABLES
          o_cd1251       = old_rows
          n_cd1251       = new_rows.
    ENDIF.
    COMMIT WORK AND WAIT.
  ENDMETHOD.

  METHOD generate.
    DATA return TYPE STANDARD TABLE OF bapiret2.
    CALL FUNCTION 'PRGN_AUTO_GENERATE_PROFILE_NEW'
      EXPORTING
        activity_group              = role
        no_dialog                   = 'X'
        rebuild_auth_data           = ' '
        fill_empty_fields_with_star = ' '
        generate_profile            = 'X'
      TABLES
        return                      = return
      EXCEPTIONS
        OTHERS                      = 1.
    generated = xsdbool( sy-subrc = 0 ).
    COMMIT WORK AND WAIT.
    add_step( EXPORTING step = `generate profile` ok = generated return = return CHANGING result = result ).
  ENDMETHOD.

  METHOD check_allowed.
    SELECT SINGLE cccategory FROM t000 WHERE mandt = @sy-mandt INTO @DATA(category).
    IF category = 'P'.
      result = |Client { sy-mandt } is a production client - role maintenance refused.|.
      RETURN.
    ENDIF.
    SELECT SINGLE @abap_true FROM agr_define WHERE agr_name = @role INTO @DATA(exists).
    IF create = abap_true AND exists = abap_true.
      result = |Role { role } exists already.|.
      RETURN.
    ELSEIF create = abap_false AND exists = abap_false.
      result = |Role { role } does not exist.|.
      RETURN.
    ENDIF.
    DATA(activity) = COND activ_auth( WHEN create = abap_true THEN '01' ELSE '02' ).
    AUTHORITY-CHECK OBJECT 'S_USER_AGR' ID 'ACT_GROUP' FIELD role ID 'ACTVT' FIELD activity.
    IF sy-subrc <> 0.
      result = |No authorization S_USER_AGR { activity } for role { role }.|.
    ENDIF.
  ENDMETHOD.

  METHOD create_role.
    DATA return   TYPE bapirettab.
    DATA messages TYPE sprot_u_tab.
    DATA texts    TYPE STANDARD TABLE OF agr_texts.
    DATA request  TYPE trkorr.
    DATA text     TYPE string.

    IF change-copy_from IS INITIAL.
      CALL FUNCTION 'PRGN_RFC_CREATE_AGR_MULTIPLE'
        EXPORTING
          activity_group      = change-role
          activity_group_text = change-description
          no_dialog           = 'X'
          request             = result-transport
        IMPORTING
          new_request         = request
        TABLES
          return              = return
        EXCEPTIONS
          OTHERS              = 1.
    ELSE.
      " no users, HR relationships, personalization or distribution: the copy starts without users
      CALL FUNCTION 'PRGN_COPY_AGR'
        EXPORTING
          source_agr        = change-copy_from
          target_agr        = change-role
          user_assinement   = ' '
          hr_assignments    = ' '
          pers_objects      = ' '
          with_distribution = ' '
          no_distrib_popup  = 'X'
          dialog            = ' '
          display_messages  = ' '
          request           = result-transport
        IMPORTING
          messages          = messages
        EXCEPTIONS
          OTHERS            = 1.
    ENDIF.
    DATA(subrc) = sy-subrc.
    IF subrc <> 0 AND sy-msgid IS NOT INITIAL.
      MESSAGE ID sy-msgid TYPE 'S' NUMBER sy-msgno WITH sy-msgv1 sy-msgv2 sy-msgv3 sy-msgv4 INTO text.
    ENDIF.
    COMMIT WORK AND WAIT.
    LOOP AT messages INTO DATA(message) WHERE severity CA 'EAW'.
      MESSAGE ID message-ag TYPE 'S' NUMBER message-msgnr WITH message-var1 message-var2 message-var3 message-var4
        INTO DATA(message_text).
      APPEND VALUE #( type = message-severity id = message-ag number = message-msgnr message = message_text ) TO return.
    ENDLOOP.
    add_step( EXPORTING step   = COND #( WHEN change-copy_from IS INITIAL THEN |create single role { change-role }|
                                         ELSE |copy { change-copy_from } to { change-role } (without users)| )
                        ok     = xsdbool( subrc = 0 )
                        return = return
                        text   = text
              CHANGING  result = result ).
    IF request IS NOT INITIAL.
      result-transport = request.
    ENDIF.
    IF subrc <> 0 OR change-copy_from IS INITIAL OR change-description IS INITIAL.
      RETURN.
    ENDIF.

    texts = VALUE #( ( spras = sy-langu line = 0 text = change-description ) ).
    CLEAR: return, text.
    CALL FUNCTION 'PRGN_RFC_CHANGE_TEXTS'
      EXPORTING
        activity_group = change-role
        no_dialog      = 'X'
        request        = result-transport
      TABLES
        texts          = texts
        return         = return
      EXCEPTIONS
        OTHERS         = 1.
    subrc = sy-subrc.
    IF subrc <> 0 AND sy-msgid IS NOT INITIAL.
      MESSAGE ID sy-msgid TYPE 'S' NUMBER sy-msgno WITH sy-msgv1 sy-msgv2 sy-msgv3 sy-msgv4 INTO text.
    ENDIF.
    COMMIT WORK AND WAIT.
    add_step( EXPORTING step = |set description of { change-role }| ok = xsdbool( subrc = 0 ) return = return text = text
              CHANGING  result = result ).
  ENDMETHOD.

  METHOD add_step.
    DATA(entry) = VALUE zif_accx_role_changer=>ty_step( step = step ok = ok ).
    IF text IS NOT INITIAL.
      APPEND text TO entry-messages.
    ENDIF.
    LOOP AT return INTO DATA(message) WHERE type CA 'EAW'.
      APPEND |{ message-type } { message-id }/{ message-number }: { message-message }| TO entry-messages.
    ENDLOOP.
    APPEND entry TO result-steps.
  ENDMETHOD.

  METHOD change_composite.
    TYPES: BEGIN OF ty_call,
             function TYPE rs38l_fnam,
             roles    TYPE string_table,
             step     TYPE string,
           END OF ty_call.
    DATA calls       TYPE STANDARD TABLE OF ty_call WITH EMPTY KEY.
    DATA singles     TYPE STANDARD TABLE OF agr_txt.
    DATA return      TYPE STANDARD TABLE OF bapiret2.
    DATA new_request TYPE trkorr.

    IF change-remove_roles IS NOT INITIAL.
      APPEND VALUE #( function = 'PRGN_RFC_DEL_AGRS_IN_COLL_AGR' roles = change-remove_roles step = `remove single roles` ) TO calls.
    ENDIF.
    IF change-add_roles IS NOT INITIAL.
      APPEND VALUE #( function = 'PRGN_RFC_ADD_AGRS_TO_COLL_AGR' roles = change-add_roles step = `add single roles` ) TO calls.
    ENDIF.

    LOOP AT calls INTO DATA(call).
      singles = VALUE #( FOR r IN call-roles ( agr_name = r ) ).
      CLEAR: return, new_request.
      " both function modules check S_USER_AGR, lock the role, record it if the client demands it,
      " save the definition and run the user comparison of the composite role
      CALL FUNCTION call-function
        EXPORTING
          activity_group                = change-role
          request                       = result-transport
          no_dialog                     = 'X'
        IMPORTING
          new_request                   = new_request
        TABLES
          activity_groups               = singles
          return                        = return
        EXCEPTIONS
          activity_group_does_not_exist = 1
          no_collective_activity_group  = 2
          activity_group_enqueued       = 3
          namespace_problem             = 4
          not_authorized                = 5
          authority_incomplete          = 6
          OTHERS                        = 7.
      DATA(subrc) = sy-subrc.
      DATA(text) = ``.
      IF subrc <> 0 AND sy-msgid IS NOT INITIAL.
        MESSAGE ID sy-msgid TYPE 'E' NUMBER sy-msgno WITH sy-msgv1 sy-msgv2 sy-msgv3 sy-msgv4 INTO text.
      ELSEIF subrc <> 0.
        text = |{ call-function } failed (exception { subrc })|.
      ENDIF.
      COMMIT WORK AND WAIT.
      add_step( EXPORTING step   = |{ call-step } { concat_lines_of( table = call-roles sep = `, ` ) } (with user comparison)|
                          ok     = xsdbool( subrc = 0 )
                          return = return
                          text   = text
                CHANGING  result = result ).
      IF new_request IS NOT INITIAL.
        result-transport = new_request.
      ENDIF.
      IF subrc <> 0.
        RETURN.
      ENDIF.
    ENDLOOP.
  ENDMETHOD.
ENDCLASS.
