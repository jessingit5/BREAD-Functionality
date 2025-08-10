from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session
from . import models, schemas, auth, hashing
from .database import engine, Base, get_db

Base.metadata.create_all(bind=engine)
app = FastAPI()
app.mount("/static", StaticFiles(directory="static"), name="static")

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

@app.post("/calculations/", response_model=schemas.CalculationRead, status_code=status.HTTP_201_CREATED)
def add_calculation(calc: schemas.CalculationCreate, db: Session = Depends(get_db), user: models.User = Depends(auth.get_current_active_user)):
    db_calc = models.Calculation(a=calc.a, b=calc.b, type=calc.type.value, user_id=user.id)
    db.add(db_calc)
    db.commit()
    db.refresh(db_calc)
    return db_calc

@app.get("/calculations/", response_model=list[schemas.CalculationRead])
def browse_calculations(db: Session = Depends(get_db), user: models.User = Depends(auth.get_current_active_user)):
    return db.query(models.Calculation).filter(models.Calculation.user_id == user.id).all()

@app.get("/calculations/{calc_id}", response_model=schemas.CalculationRead)
def read_calculation(calc_id: int, db: Session = Depends(get_db), user: models.User = Depends(auth.get_current_active_user)):
    db_calc = db.query(models.Calculation).filter(models.Calculation.id == calc_id, models.Calculation.user_id == user.id).first()
    if not db_calc:
        raise HTTPException(status_code=404, detail="Calculation not found")
    return db_calc

@app.put("/calculations/{calc_id}", response_model=schemas.CalculationRead)
def edit_calculation(calc_id: int, calc: schemas.CalculationUpdate, db: Session = Depends(get_db), user: models.User = Depends(auth.get_current_active_user)):
    db_calc = db.query(models.Calculation).filter(models.Calculation.id == calc_id, models.Calculation.user_id == user.id).first()
    if not db_calc:
        raise HTTPException(status_code=404, detail="Calculation not found")
    
    db_calc.a = calc.a
    db_calc.b = calc.b
    db_calc.type = calc.type.value
    db.commit()
    db.refresh(db_calc)
    return db_calc

@app.delete("/calculations/{calc_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_calculation(calc_id: int, db: Session = Depends(get_db), user: models.User = Depends(auth.get_current_active_user)):
    db_calc = db.query(models.Calculation).filter(models.Calculation.id == calc_id, models.Calculation.user_id == user.id).first()
    if not db_calc:
        raise HTTPException(status_code=404, detail="Calculation not found")
    
    db.delete(db_calc)
    db.commit()
    return {"ok": True}