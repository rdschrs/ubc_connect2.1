from pydantic import BaseModel, EmailStr
from typing import Optional, List
from datetime import datetime


# --- COMMENT SCHEMAS (NEW) ---
class CommentCreate(BaseModel):
    content: str

class CommentOut(BaseModel):
    id: int
    content: str
    timestamp: datetime
    user_id: int
    # We optionally include the user's name so we know who commented
    # (Advanced Pydantic nesting can be done here, but let's keep it simple)
    
    class Config:
        from_attributes = True

# 1. Base Schema (Shared properties)
class UserBase(BaseModel):
    email: EmailStr
    full_name: Optional[str] = None
    program: Optional[str] = None
    year_standing: Optional[int] = None
    residence: Optional[str] = None
    
    # New Social & Privacy Fields
    instagram_handle: Optional[str] = None
    interests: Optional[str] = None
    show_email: bool = False
    show_attending: bool = True


# 2. Schema for CREATING a user (Input)
# We need the password here, but we NEVER save it as plain text.
class UserCreate(UserBase):
    password: str


class UserUpdate(BaseModel): # <--- NEW: For editing profile
    full_name: Optional[str] = None
    program: Optional[str] = None
    year_standing: Optional[int] = None
    residence: Optional[str] = None

    # New Fields
    instagram_handle: Optional[str] = None
    interests: Optional[str] = None
    show_email: Optional[bool] = None
    show_attending: Optional[bool] = None

# 3. Schema for READING a user (Output)
# We return the user info but EXCLUDE the password for security.
class UserOut(UserBase):
    id: int
    is_active: bool
    is_staff: bool # We can show if they are staff, but not let them change it
    role: str # "student" or "organization"    

    # We add these counts so the profile can show "5 Followers"
    followers_count: int = 0
    following_count: int = 0
    
    class Config:
        from_attributes = True

# 2. Create a "Public Profile" Schema (What others see)
class PublicUserOut(BaseModel):
    id: int
    full_name: Optional[str]
    program: Optional[str]
    year_standing: Optional[int]
    residence: Optional[str]
    # New Social Fields
    instagram_handle: Optional[str]
    interests: Optional[str]
    
    # These might be Hidden/None depending on privacy
    email: Optional[str] = None 
    
    class Config:
        from_attributes = True

# --- NEW: Token Schemas ---
class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    email: Optional[str] = None

class EventBase(BaseModel):
    title: str
    description: Optional[str] = None
    location: str
    date_time: datetime
    image_url: Optional[str] = None # <--- Add this (Defaults to None)
    max_capacity: Optional[int] = None # <--- NEW

class EventCreate(EventBase):
    ticket_price: Optional[int] = 0
    # User can optionally send a list of IDs for co-hosts and scanners
    co_host_emails: List[str] = [] 
    scanner_emails: List[str] = []

class EventOut(EventBase):
    id: int
    ticket_price: int
    # We display the list of hosts (so frontend can show "Hosts: Alice, UBC Ski Club")
    hosts: List[UserOut]
    # We display scanners so the creator knows who is on the team
    scanners: List[UserOut]
    is_approved: bool # Show the status
    image_url: Optional[str] # <--- Add this too
    attendees_count: int = 0 # <--- NEW: Nice to have for frontend

    class Config:
        from_attributes = True

# --- NOTIFICATION SCHEMAS ---
class NotificationOut(BaseModel):
    id: int
    message: str
    is_read: bool
    timestamp: datetime
    class Config:
        from_attributes = True

# --- FORUM SCHEMAS ---
class ForumPostCreate(BaseModel):
    title: str
    content: str
    category: str # e.g. "Study", "Sports"

class ForumPostOut(BaseModel):
    id: int
    title: str
    content: str
    category: str
    timestamp: datetime
    author_id: int
    # We will show the author's name
    class Config:
        from_attributes = True

# --- NEW TICKET SCHEMA ---
class TicketOut(BaseModel):
    unique_code: str
    is_used: bool
    event_title: str # Helper to show which event this is for

# --- ADMIN ANALYTICS ---
class AdminStats(BaseModel):
    total_users: int
    active_users: int
    total_events: int
    pending_approvals: int
    total_comments: int
    most_popular_event: Optional[str] = None # Title of the biggest event