from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from . import models, schemas, auth, hashing
from .database import SessionLocal, engine, Base 


Base.metadata.create_all(bind=engine)

app = FastAPI()

app.mount("/static", StaticFiles(directory="static"), name="static")


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@app.get("/", response_class=FileResponse, include_in_schema=False)
async def read_root():
    return FileResponse('static/login.html')

@app.post("/register", response_model=schemas.UserRead, status_code=status.HTTP_201_CREATED)
def register_user(user: schemas.UserCreate, db: Session = Depends(get_db)):
    db_user = db.query(models.User).filter(models.User.email == user.email).first()
    if db_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    hashed_password = hashing.Hasher.hash_password(user.password)
    new_user = models.User(username=user.username, email=user.email, hashed_password=hashed_password)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return new_user

@app.post("/login")
def login_for_access_token(form_data: schemas.UserLogin, db: Session = Depends(get_db)):
    user = auth.authenticate_user(db, form_data.email, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
        )
    access_token = auth.create_access_token(data={"sub": user.email})
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/calculations/", response_model=schemas.CalculationRead, status_code=status.HTTP_21_CREATED)
def add_calculation(
    calculation: schemas.CalculationCreate,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(auth.get_current_active_user)
):
    db_calculation = models.Calculation(**calculation.model_dump(), user_id=current_user.id)
    db.add(db_calculation)
    db.commit()
    db.refresh(db_calculation)
    return db_calculation

@app.get("/calculations/", response_model=list[schemas.CalculationRead])
def browse_calculations(
    db: Session = Depends(get_db),
    current_user: models.User = Depends(auth.get_current_active_user)
):
    return db.query(models.Calculation).filter(models.Calculation.user_id == current_user.id).all()

@app.get("/calculations/{calculation_id}", response_model=schemas.CalculationRead)
def read_calculation(
    calculation_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(auth.get_current_active_user)
):
    db_calculation = db.query(models.Calculation).filter(
        models.Calculation.id == calculation_id,
        models.Calculation.user_id == current_user.id
    ).first()
    if db_calculation is None:
        raise HTTPException(status_code=404, detail="Calculation not found")
    return db_calculation

@app.put("/calculations/{calculation_id}", response_model=schemas.CalculationRead)
def edit_calculation(
    calculation_id: int,
    calculation: schemas.CalculationUpdate,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(auth.get_current_active_user)
):
    db_calculation = db.query(models.Calculation).filter(
        models.Calculation.id == calculation_id,
        models.Calculation.user_id == current_user.id
    ).first()
    if db_calculation is None:
        raise HTTPException(status_code=404, detail="Calculation not found")
    
    db_calculation.a = calculation.a
    db_calculation.b = calculation.b
    db_calculation.type = calculation.type.value
    db.commit()
    db.refresh(db_calculation)
    return db_calculation

@app.delete("/calculations/{calculation_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_calculation(
    calculation_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(auth.get_current_active_user)
):
    db_calculation = db.query(models.Calculation).filter(
        models.Calculation.id == calculation_id,
        models.Calculation.user_id == current_user.id
    ).first()
    if db_calculation is None:
        raise HTTPException(status_code=404, detail="Calculation not found")
        
    db.delete(db_calculation)
    db.commit()
    return {"ok": True}