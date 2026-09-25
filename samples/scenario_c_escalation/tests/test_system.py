from app.system import choose_program


def test_program_selection_contract():
    assert choose_program() == "echo"
