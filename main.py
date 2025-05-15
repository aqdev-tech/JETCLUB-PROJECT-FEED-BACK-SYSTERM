import os
from datetime import datetime, timedelta
from typing import List, Optional

from dotenv import load_dotenv
from fastapi import Depends, FastAPI, HTTPException, status, Request
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from jose import JWTError, jwt
from motor.motor_asyncio import AsyncIOMotorClient
from pydantic import BaseModel, Field
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

# Load environment variables
load_dotenv()

# Initialize FastAPI
app = FastAPI(title="Anonymous Feedback API")

# Rate limiting setup
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# CORS (adjust as needed)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# MongoDB setup
MONGO_URI = os.getenv("MONGO_URI")
client = AsyncIOMotorClient(MONGO_URI)
db = client.feedback_db
feedbacks_collection = db.feedbacks

# JWT setup
JWT_SECRET = os.getenv("JWT_SECRET")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="admin/login")

# Banned words list
BANNED_WORDS = ["stupid", "idiot", "useless", "dumb"]

# Pydantic models
class FeedbackCreate(BaseModel):
    category: str = Field(..., min_length=1, max_length=50)
    message: str = Field(..., min_length=1, max_length=1000)

class FeedbackOut(FeedbackCreate):
    id: str
    sanitized_message: str
    status: str
    created_at: datetime

class FeedbackUpdate(BaseModel):
    status: str = Field(..., pattern="^(read|important|resolved)$")

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: str

# Helper functions
def sanitize_message(message: str) -> str:
    words = message.split()
    sanitized_words = []
    for word in words:
        lower_word = word.lower()
        if any(banned_word in lower_word for banned_word in BANNED_WORDS):
            sanitized_words.append("***")
        else:
            sanitized_words.append(word)
    return " ".join(sanitized_words)

async def authenticate_user(username: str, password: str):
    if username == os.getenv("ADMIN_USERNAME") and password == os.getenv("ADMIN_PASSWORD"):
        return {"username": username}
    return None

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, JWT_SECRET, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception
    
    if token_data.username != os.getenv("ADMIN_USERNAME"):
        raise credentials_exception
    return token_data

# Routes
@app.get("/", response_model=dict)
async def root():
    return {"msg": "Anon Feedback API Active"}
 
@app.post("/feedback", response_model=FeedbackOut)
@limiter.limit("3/minute")
async def create_feedback(
    request: Request,
    feedback: FeedbackCreate,
):
    sanitized_message = sanitize_message(feedback.message)
    feedback_data = {
        "category": feedback.category,
        "message": feedback.message,
        "sanitized_message": sanitized_message,
        "status": "unread",
        "created_at": datetime.utcnow(),
    }
    result = await feedbacks_collection.insert_one(feedback_data)
    feedback_data["id"] = str(result.inserted_id)
    return feedback_data

@app.post("/admin/login", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = await authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user["username"]}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/admin/feedbacks", response_model=List[FeedbackOut])
async def list_feedbacks(
    current_user: TokenData = Depends(get_current_user),
    category: Optional[str] = None,
):
    query = {}
    if category:
        query["category"] = category
    feedbacks = []
    async for feedback in feedbacks_collection.find(query).sort("created_at", -1):
        feedback["id"] = str(feedback["_id"])
        feedbacks.append(feedback)
    return feedbacks

@app.patch("/admin/feedbacks/{feedback_id}", response_model=FeedbackOut)
async def update_feedback_status(
    feedback_id: str,
    update: FeedbackUpdate,
    current_user: TokenData = Depends(get_current_user),
):
    result = await feedbacks_collection.update_one(
        {"_id": feedback_id},
        {"$set": {"status": update.status}},
    )
    if result.modified_count == 0:
        raise HTTPException(status_code=404, detail="Feedback not found")
    
    updated_feedback = await feedbacks_collection.find_one({"_id": feedback_id})
    updated_feedback["id"] = str(updated_feedback["_id"])
    return updated_feedback

# Run with: uvicorn main:app --reload