import pytest
from sqlalchemy.orm import Session
from app.models.calculation import Calculation
from app.models.user import User
from app.schemas.calculation import CalculationRead
from app.hashing import Hasher
import time

def test_create_and_read_calculation(db_session: Session):

    unique_username = f"testuser_{int(time.time())}"
    unique_email = f"test_{int(time.time())}@example.com"

    test_user = User(
        username=unique_username,
        email=unique_email,
        hashed_password=Hasher.hash_password("password123")
    )
    db_session.add(test_user)
    db_session.commit()
    db_session.refresh(test_user)

    new_calc = Calculation(a=100, b=25, type="divide", user_id=test_user.id)
    db_session.add(new_calc)
    db_session.commit()
    db_session.refresh(new_calc)

    assert new_calc.id is not None
    assert new_calc.a == 100
    assert new_calc.type == "divide"
    assert new_calc.owner.username == unique_username

