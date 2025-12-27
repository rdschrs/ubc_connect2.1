from sqlalchemy import Column, Integer, String, Boolean, ForeignKey, DateTime, Text, Table
from sqlalchemy.orm import relationship
from .database import Base
import datetime

# Association Table (RSVPs)

# 1. Hosts (Organizers & Clubs)
event_hosts = Table("event_hosts", Base.metadata,
    Column("user_id", Integer, ForeignKey("users.id"), primary_key=True),
    Column("event_id", Integer, ForeignKey("events.id"), primary_key=True)
)

# 2. Scanners (Staff who check tickets)
event_scanners = Table("event_scanners", Base.metadata,
    Column("user_id", Integer, ForeignKey("users.id"), primary_key=True),
    Column("event_id", Integer, ForeignKey("events.id"), primary_key=True)
)

event_attendees = Table(
    "event_attendees",
    Base.metadata,
    Column("user_id", Integer, ForeignKey("users.id"), primary_key=True),
    Column("event_id", Integer, ForeignKey("events.id"), primary_key=True)
)


user_follows = Table(
    "user_follows",
    Base.metadata,
    Column("follower_id", Integer, ForeignKey("users.id"), primary_key=True),
    Column("followed_id", Integer, ForeignKey("users.id"), primary_key=True)
)

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    
    # --- EXISTING PROFILE FIELDS (KEPT) ---
    full_name = Column(String, nullable=True)
    program = Column(String, nullable=True)
    year_standing = Column(Integer, nullable=True)
    residence = Column(String, nullable=True)
        # --- NEW: SOCIAL PROFILE ---
    instagram_handle = Column(String, nullable=True) # e.g. "@ubc_student"
    interests = Column(String, nullable=True)        # e.g. "Hiking, Coding, Sushi"
    
    # --- NEW: PRIVACY SETTINGS ---
    show_email = Column(Boolean, default=False)      # Default: Hide email from public
    show_attending = Column(Boolean, default=True)   # Default: Show my events to friends

    
    
    # --- SECURITY & STATUS ---
    is_active = Column(Boolean, default=False) # Must be True to login
    verification_code = Column(String, nullable=True)
    role = Column(String, default="student") # "student" or "organization" (Manual Official Accounts)
    is_staff = Column(Boolean, default=False) # App Admin


    # Relationships
    # Note: We removed 'events' (singular owner) and replaced it with 'hosted_events' (multiple hosts)
    hosted_events = relationship("Event", secondary=event_hosts, back_populates="hosts")
    scannable_events = relationship("Event", secondary=event_scanners, back_populates="scanners")
    
    attending = relationship("Event", secondary=event_attendees, back_populates="attendees")
    forum_posts = relationship("ForumPost", back_populates="author")
    comments = relationship("Comment", back_populates="user")
    tickets = relationship("Ticket", back_populates="user") # <--- NEW
    
    # Notifications & Following
    notifications = relationship("Notification", back_populates="user")
    following = relationship(
        "User", 
        secondary=user_follows,
        primaryjoin=id==user_follows.c.follower_id,
        secondaryjoin=id==user_follows.c.followed_id,
        backref="followers"
    )

class Event(Base):
    __tablename__ = "events"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String, index=True, nullable=False)
    description = Column(Text, nullable=True)
    location = Column(String, nullable=False)
    date_time = Column(DateTime, nullable=False)
    organizer_id = Column(Integer, ForeignKey("users.id"))
    is_approved = Column(Boolean, default=False)
    image_url = Column(String, nullable=True)

    # Ticketing
    max_capacity = Column(Integer, nullable=True)
    ticket_price = Column(Integer, default=0) # In cents; 0 = free

    # --- NEW: Team Management ---
    # We removed 'organizer_id'. Now we have a list of hosts.
    hosts = relationship("User", secondary=event_hosts, back_populates="hosted_events")
    scanners = relationship("User", secondary=event_scanners, back_populates="scannable_events")
    
    attendees = relationship("User", secondary=event_attendees, back_populates="attending")
    comments = relationship("Comment", back_populates="event")
    tickets = relationship("Ticket", back_populates="event") # <--- NEW

# --- NEW: Comment Table ---
class Comment(Base):
    __tablename__ = "comments"

    id = Column(Integer, primary_key=True, index=True)
    content = Column(String, nullable=False)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)
    
    user_id = Column(Integer, ForeignKey("users.id"))
    event_id = Column(Integer, ForeignKey("events.id"))

    user = relationship("User", back_populates="comments")
    event = relationship("Event", back_populates="comments")

# --- NEW: Notification Table ---
class Notification(Base):
    __tablename__ = "notifications"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id")) # Who gets the alert?
    message = Column(String, nullable=False)
    is_read = Column(Boolean, default=False)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)
    
    user = relationship("User", back_populates="notifications")

# --- NEW: Forum Post Table ---
class ForumPost(Base):
    __tablename__ = "forum_posts"
    
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String, nullable=False)
    content = Column(Text, nullable=False)
    category = Column(String, nullable=False) # "Study", "Social", "Sports"
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)
    
    author_id = Column(Integer, ForeignKey("users.id"))
    author = relationship("User", back_populates="forum_posts")

class Ticket(Base):
    __tablename__ = "tickets"
    
    id = Column(Integer, primary_key=True, index=True)
    unique_code = Column(String, unique=True, index=True, default=lambda: str(uuid.uuid4())) # The QR Code Data
    is_used = Column(Boolean, default=False) # Has it been scanned yet?
    
    user_id = Column(Integer, ForeignKey("users.id"))
    event_id = Column(Integer, ForeignKey("events.id"))
    
    user = relationship("User", back_populates="tickets")
    event = relationship("Event", back_populates="tickets")