import pytest
from pydantic import ValidationError
from app.schemas.calculation import CalculationCreate, CalculationType
from app.core.factory import CalculationFactory, Add, Subtract, Multiply, Divide

def test_factory_get_operation():
    assert CalculationFactory.get_operation("add") is Add
    assert CalculationFactory.get_operation("subtract") is Subtract
    assert CalculationFactory.get_operation("multiply") is Multiply
    assert CalculationFactory.get_operation("divide") is Divide

def test_factory_invalid_operation():
    with pytest.raises(KeyError):
        CalculationFactory.get_operation("power")

def test_operations_execute():
    assert Add(10, 5).execute() == 15
    assert Subtract(10, 5).execute() == 5
    assert Multiply(10, 5).execute() == 50
    assert Divide(10, 5).execute() == 2

def test_pydantic_validation_divide_by_zero():
    with pytest.raises(ValidationError) as excinfo:
        CalculationCreate(a=10, b=0, type=CalculationType.DIVIDE)
    assert "Division by zero is not allowed" in str(excinfo.value)

def test_pydantic_validation_valid_data():
    schema = CalculationCreate(a=10, b=5, type=CalculationType.ADD)
    assert schema.a == 10
    assert schema.b == 5
    assert schema.type == "add"