"! <p class="shorttext synchronized">Access Explorer: plugin ADMIN factory and test seam</p>
CLASS zcl_accx_admin_factory DEFINITION PUBLIC FINAL CREATE PRIVATE.

  PUBLIC SECTION.
    CLASS-METHODS role_changer
      RETURNING VALUE(result) TYPE REF TO zif_accx_role_changer.

    CLASS-METHODS assignment_writer
      RETURNING VALUE(result) TYPE REF TO zif_accx_assignment_writer.

    "! Test seam: replace services (unbound parameters keep the current value)
    CLASS-METHODS inject
      IMPORTING !role_changer      TYPE REF TO zif_accx_role_changer OPTIONAL
                !assignment_writer TYPE REF TO zif_accx_assignment_writer OPTIONAL.

    CLASS-METHODS reset.

  PRIVATE SECTION.
    CLASS-DATA role_changer_override      TYPE REF TO zif_accx_role_changer.
    CLASS-DATA assignment_writer_override TYPE REF TO zif_accx_assignment_writer.

ENDCLASS.

CLASS zcl_accx_admin_factory IMPLEMENTATION.

  METHOD role_changer.
    IF role_changer_override IS BOUND.
      result = role_changer_override.
    ELSE.
      result = NEW zcl_accx_role_changer( ).
    ENDIF.
  ENDMETHOD.

  METHOD assignment_writer.
    IF assignment_writer_override IS BOUND.
      result = assignment_writer_override.
    ELSE.
      result = NEW zcl_accx_assignment_writer( ).
    ENDIF.
  ENDMETHOD.

  METHOD inject.
    IF role_changer IS BOUND.
      role_changer_override = role_changer.
    ENDIF.
    IF assignment_writer IS BOUND.
      assignment_writer_override = assignment_writer.
    ENDIF.
  ENDMETHOD.

  METHOD reset.
    CLEAR: role_changer_override, assignment_writer_override.
  ENDMETHOD.

ENDCLASS.
