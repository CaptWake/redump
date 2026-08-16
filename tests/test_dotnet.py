from types import SimpleNamespace

from redump.extractors.dotnet import _format_cil_instruction


def instruction(offset, name, operand_type, operand=None):
    return SimpleNamespace(
        offset=offset,
        operand=operand,
        opcode=SimpleNamespace(
            name=name, operand_type=SimpleNamespace(name=operand_type)
        ),
    )


def test_cil_offsets_are_relative_to_method_code():
    insn = instruction(0x120D, "ret", "InlineNone")
    assert _format_cil_instruction(insn, 0x120D) == "IL_0000: ret"


def test_cil_branch_targets_are_rendered_as_il_offsets():
    insn = instruction(0x120D, "br.s", "ShortInlineBrTarget", 0x1212)
    assert _format_cil_instruction(insn, 0x120D) == "IL_0000: br.s IL_0005"


def test_cil_switch_targets_are_rendered_as_il_offsets():
    insn = instruction(0x120D, "switch", "InlineSwitch", [0x1212, 0x1218])
    assert _format_cil_instruction(insn, 0x120D) == (
        "IL_0000: switch (IL_0005, IL_000B)"
    )
