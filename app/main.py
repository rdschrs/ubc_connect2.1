import os
# --- DEBUG START ---
print("🔍--- STARTING DEBUG ---")
print("I am running in directory:", os.getcwd())
print("Do I see MAIL_USERNAME?", "MAIL_USERNAME" in os.environ)
if "MAIL_USERNAME" in os.environ:
    print("MAIL_USERNAME value is:", os.environ["MAIL_USERNAME"])
else:
    print("❌ ERROR: MAIL_USERNAME is MISSING from environment variables!")
print("🔍--- END DEBUG ---")
# --- DEBUG END ---

from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
import datetime 
from datetime import timedelta
from fastapi import FastAPI, Depends, HTTPException, status, UploadFile, File, BackgroundTasks, Request
from sqlalchemy.orm import Session
from . import models, database, schemas, utils
from typing import List, Optional
from . import email_utils
from pydantic import BaseModel
import shutil
import uuid # To generate unique filenames
from fastapi.staticfiles import StaticFiles # To serve images
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from apscheduler.schedulers.background import BackgroundScheduler
from sqlalchemy import func
from fastapi.responses import RedirectResponse, HTMLResponse # <--- Add this

# Create Tables
#models.Base.metadata.drop_all(bind=database.engine)
models.Base.metadata.create_all(bind=database.engine)
limiter = Limiter(key_func=get_remote_address) # Rate Limiter

app = FastAPI(title="UBC Connect Backend")

# This tells the server: "If someone asks for /static/..., show them the files in the static folder"
app.mount("/static", StaticFiles(directory="static"), name="static")
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Dependency
def get_db():
    db = database.SessionLocal()
    try:
        yield db
    finally:
        db.close()

# --- NEW: Registration Endpoint ---
@app.post("/users/", response_model=schemas.UserOut)
@limiter.limit("2/minute") # <--- ADD THIS
async def create_user(
    request: Request,
    user: schemas.UserCreate, 
    background_tasks: BackgroundTasks, 
    db: Session = Depends(get_db)
):
    # 1. Check existing email
    db_user = db.query(models.User).filter(models.User.email == user.email).first()
    if db_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    # 3. Generate Verification Token (UUID)
    # This creates a string like: "f47ac10b-58cc-4372-a567-0e02b2c3d479"
    verification_token = str(uuid.uuid4())
    
    # 3. Create User 
    hashed_pwd = utils.hash_password(user.password)
    new_user = models.User(
        email=user.email,
        hashed_password=hashed_pwd,
        full_name=user.full_name,
        program=user.program,
        year_standing=user.year_standing,
        residence=user.residence,
        is_active=False, # Inactive until email verified
        verification_code=verification_token, # Store the token here
        role="student"
    )
    
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    
   # 5. "Send" Email Link (Print to console)
    # NOTE: When you deploy, change "http://127.0.0.1:8000" to your real URL
    link = f"http://127.0.0.1:8000/verify-email?token={verification_token}"
    print(f"\n📨 SENDING EMAIL TO {user.email}")
    print(f"👉 Click here to verify: {link}\n")
    
    return new_user

@app.post("/token", response_model=schemas.Token)
@limiter.limit("5/minute") # <--- ADD THIS
def login_for_access_token(request: Request, form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    # 1. Find the user
    user = db.query(models.User).filter(models.User.email == form_data.username).first()

    # 2. Check credentials
    if not user or not utils.verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # 3. --- NEW CHECK: Is the email verified? ---
    if not user.is_active:
         raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email not verified. Please check your inbox for the code.",
        )

    # 4. Create the Wristband (Token)
    access_token_expires = timedelta(minutes=utils.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = utils.create_access_token(
        data={"sub": user.email}, expires_delta=access_token_expires
    )

    return {"access_token": access_token, "token_type": "bearer"}
"""
class VerifyRequest(BaseModel):
    email: str
    code: str

@app.post("/verify")
def verify_user(request: VerifyRequest, db: Session = Depends(get_db)):
    # 1. Find User
    user = db.query(models.User).filter(models.User.email == request.email).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # 2. Check if already active
    if user.is_active:
        return {"message": "Account already active"}

    # 3. Check Code
    if user.verification_code != request.code:
        raise HTTPException(status_code=400, detail="Invalid verification code")
    
    # 4. Unlock Account
    user.is_active = True
    user.verification_code = None # Clear the code
    db.commit()
    
    return {"message": "Account verified successfully! You can now log in."}
"""

@app.get("/verify-email", response_class=HTMLResponse)
def verify_email_link(token: str, db: Session = Depends(get_db)):
    # 1. Debug Print: Let's see what token the server received
    print(f"🔍 CHECKING TOKEN: {token}")
    
    # 2. Search for the user
    user = db.query(models.User).filter(models.User.verification_code == token).first()
    
    if not user:
        print("❌ ERROR: User not found with this token.")
        return """
        <h1 style='color: red;'>❌ Verification Failed</h1>
        <p>Token invalid or user already verified.</p>
        """

    # 3. Success Logic
    print(f"✅ FOUND USER: {user.email}. Activating now...")
    user.is_active = True
    user.verification_code = None # Clear the token
    db.commit()
    
    return f"""
    <h1 style='color: green;'>✅ Success!</h1>
    <p>User <b>{user.email}</b> has been verified.</p>
    <p>You can now go to Postman/Docs and log in.</p>
    """

# View My Profile
@app.get("/users/me", response_model=schemas.UserOut)
def read_users_me(current_user: models.User = Depends(utils.get_current_user)):
    return current_user

# Edit My Profile
@app.patch("/users/me", response_model=schemas.UserOut)
def update_user_me(
    user_update: schemas.UserUpdate,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(utils.get_current_user)
):
    # --- FIX: Adopt the user into this session ---
    current_user = db.merge(current_user)
    # ---------------------------------------------
    # Update only the fields sent by the user
    user_data = user_update.dict(exclude_unset=True)
    for key, value in user_data.items():
        setattr(current_user, key, value)
    
    db.add(current_user)
    db.commit()
    db.refresh(current_user)
    return current_user


# 2. READ All Events (The "Discovery Feed")
# (Public: Anyone can see events, or you can add Depends(...) to make it private)

@app.get("/users/{user_id}/profile", response_model=schemas.PublicUserOut)
def read_public_profile(user_id: int, db: Session = Depends(get_db)):
    user = db.query(models.User).filter(models.User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
        
    # --- PRIVACY LOGIC ---
    # Create a copy of data to return
    profile_data = {
        "id": user.id,
        "full_name": user.full_name,
        "faculty": user.faculty,
        "instagram_handle": user.instagram_handle,
        "interests": user.interests,
        "email": None # Default to hidden
    }
    
    # Only reveal email if they allowed it
    if user.show_email:
        profile_data["email"] = user.email
        
    return profile_data

@app.post("/events/", response_model=schemas.EventOut)
def create_event(
    event: schemas.EventCreate, 
    db: Session = Depends(get_db), 
    current_user: models.User = Depends(utils.get_current_user)
):

    # 2. Create the Event Object
    new_event = models.Event(
        title=event.title,
        description=event.description,
        location=event.location,
        date_time=event.date_time,
        image_url=event.image_url,
        max_capacity=event.max_capacity,
        ticket_price=event.ticket_price
    )
    
    # 3. Add the Creator as the First Host
    new_event.hosts.append(current_user)
    
    # 4. Add Co-Hosts (By Email)
    for email in event.co_host_emails:
        co_host = db.query(models.User).filter(models.User.email == email).first()
        if co_host:
            new_event.hosts.append(co_host)
            
    # 5. Add Scanners (By Email)
    for email in event.scanner_emails:
        scanner = db.query(models.User).filter(models.User.email == email).first()
        if scanner:
            new_event.scanners.append(scanner)

    db.add(new_event)
    db.commit()
    db.refresh(new_event)
    return new_event

@app.post("/upload-image/")
@limiter.limit("5/minute") # <--- ADD THIS
async def upload_image(request: Request, file: UploadFile = File(...)):
    # 1. Validate the file (Check if it's an image)
    if not file.content_type.startswith("image/"):
        raise HTTPException(status_code=400, detail="File must be an image")
    
    # 2. Generate a unique filename (so "party.jpg" doesn't overwrite another "party.jpg")
    # Result: "images/a1b2c3d4-party.jpg"
    file_extension = file.filename.split(".")[-1]
    unique_filename = f"{uuid.uuid4()}.{file_extension}"
    file_path = f"static/images/{unique_filename}"
    
    # 3. Save the file to your disk
    with open(file_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)
        
    # 4. Return the URL
    # In production, this would be "https://ubcconnect.com/static/..."
    return {"url": f"/static/images/{unique_filename}"}


@app.delete("/events/{event_id}")
def delete_event(
    event_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(utils.get_current_user)
):
    # 1. Find the Event
    event = db.query(models.Event).filter(models.Event.id == event_id).first()
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")

    # 2. Permission Check
    # Allow deletion if: User is Admin (Staff) OR User is one of the Hosts
    is_admin = current_user.is_staff
    # Check if current user is in the list of hosts
    is_host = any(host.id == current_user.id for host in event.hosts)

    if not (is_admin or is_host):
         raise HTTPException(
             status_code=403, 
             detail="Not authorized. Only the Event Host or an Admin can delete this event."
         )

    # 3. Delete It
    db.delete(event)
    db.commit()
    
    return {"message": f"Event '{event.title}' has been deleted."}

"""
@app.patch("/events/{event_id}/approve", response_model=schemas.EventOut)
def approve_event(
    event_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(utils.get_current_user)
):
    # 1. Security Check: Are you staff?
    if not current_user.is_staff:
        raise HTTPException(status_code=403, detail="Only staff can approve events")

    # 2. Find Event
    event = db.query(models.Event).filter(models.Event.id == event_id).first()
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")

    # 3. Approve it
    event.is_approved = True
    db.commit()
    db.refresh(event)
    return event
"""
# RSVP to an Event
@app.post("/events/{event_id}/rsvp")
def rsvp_event(
    event_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(utils.get_current_user)
):
    # --- THE FIX IS HERE ---
    # We "merge" the user from the security session into the current session
    current_user = db.merge(current_user)
    # -----------------------

    # 1. Get the event
    event = db.query(models.Event).filter(models.Event.id == event_id).first()
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")
    # 1. Check Capacity
    if (event.max_capacity and len(event.attendees)) >= event.max_capacity:
        raise HTTPException(status_code=400, detail="Event is Sold Out!")
    # 2. Check if already RSVP'd (prevent duplicates)
    if current_user in event.attendees:
        return {"message": "You are already registered for this event!"}
    
    # 3. Add user to attendees list
    event.attendees.append(current_user)

    # --- NEW: GENERATE TICKET ---
    new_ticket = models.Ticket(user_id=current_user.id, event_id=event.id)
    db.add(new_ticket)
    # ----------------------------

    db.commit()
    
    return {"message": f"Successfully RSVP'd to {event.title}. Your Ticket QR Code has been generated."}

# Scan a Ticket (by Scanner or Host)
@app.post("/events/{event_id}/scan")
def scan_ticket(
    event_id: int,
    ticket_code: str, # The string from the QR code
    db: Session = Depends(get_db),
    current_user: models.User = Depends(utils.get_current_user)
):
    event = db.query(models.Event).filter(models.Event.id == event_id).first()
    
    # 1. Check if the current user is a designated Scanner or Host
    is_scanner = current_user in event.scanners
    is_host = current_user in event.hosts
    if not (is_scanner or is_host):
         raise HTTPException(status_code=403, detail="You are not authorized to scan tickets for this event.")
         
    # 2. Find the ticket
    ticket = db.query(models.Ticket).filter(
        models.Ticket.unique_code == ticket_code,
        models.Ticket.event_id == event_id
    ).first()
    
    if not ticket:
        raise HTTPException(status_code=404, detail="Invalid Ticket")
        
    if ticket.is_used:
        raise HTTPException(status_code=400, detail="ALREADY USED! Ticket has already been scanned.")
        
    # 3. Mark as Used
    ticket.is_used = True
    db.commit()
    
    return {
        "status": "VALID", 
        "attendee": ticket.user.full_name or ticket.user.email,
        "message": "Welcome in!"
    }

# View who is attending an event
@app.get("/events/{event_id}/attendees", response_model=List[schemas.UserOut])
def read_event_attendees(event_id: int, db: Session = Depends(get_db)):
    # 1. Find the event
    event = db.query(models.Event).filter(models.Event.id == event_id).first()
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")
    
    # 2. Return the list of users (SQLAlchemy handles the join automatically!)
    return event.attendees

@app.get("/users/recommendations", response_model=List[schemas.PublicUserOut])
def get_friend_recommendations(
    db: Session = Depends(get_db),
    current_user: models.User = Depends(utils.get_current_user)
):
    # 1. PREPARE MY DATA
    # Get my event IDs
    my_event_ids = {event.id for event in current_user.attending}
    
    # Get my interests as a Set (normalized to lowercase)
    my_interests = set()
    if current_user.interests:
        # "Hiking, Sushi,  Code " -> {"hiking", "sushi", "code"}
        my_interests = {tag.strip().lower() for tag in current_user.interests.split(",")}

    # 2. GET CANDIDATES
    # We fetch ALL other users so we can match by Interest even if they aren't in my events yet
    candidates = db.query(models.User).filter(models.User.id != current_user.id).all()
    
    scored_users = []

    # 3. CALCULATE SCORES
    for user in candidates:
        score = 0
        
        # --- SCORE FACTOR A: SHARED INTERESTS (+10 pts each) ---
        if user.interests:
            their_interests = {tag.strip().lower() for tag in user.interests.split(",")}
            # Find intersection
            shared_interests = my_interests.intersection(their_interests)
            score += len(shared_interests) * 10
            
        # --- SCORE FACTOR B: SHARED EVENTS (+5 pts each) ---
        # (Only calculate if we actually have events to compare)
        if my_event_ids:
            their_event_ids = {event.id for event in user.attending}
            shared_events = my_event_ids.intersection(their_event_ids)
            score += len(shared_events) * 5
            
        # If they have any compatibility, add them to the list
        if score > 0:
            scored_users.append((user, score))
    
    # 4. RANKING
    # Sort by Score (Highest first)
    scored_users.sort(key=lambda x: x[1], reverse=True)
    
    # 5. Return top 5 users
    # We extract just the User object from the (User, Score) tuple
    top_matches = [item[0] for item in scored_users[:5]]
    
    return top_matches
# Follow a User

@app.post("/users/{user_id}/follow")
def follow_user(
    user_id: int, 
    db: Session = Depends(get_db), 
    current_user: models.User = Depends(utils.get_current_user)
):
    
    # --- FIX: Adopt the user into this session ---
    current_user = db.merge(current_user)
    # ---------------------------------------------

    # 1. Who are we trying to follow?
    target_user = db.query(models.User).filter(models.User.id == user_id).first()
    if not target_user:
        raise HTTPException(status_code=404, detail="User not found")
        
    if target_user.id == current_user.id:
        raise HTTPException(status_code=400, detail="You cannot follow yourself")

    # 2. Check if already following
    if target_user in current_user.following:
        return {"message": "You are already following this user"}
        
    # 3. Follow them
    current_user.following.append(target_user)
    
    # 4. --- TRIGGER NOTIFICATION ---
    # Create an alert for the person being followed
    new_notif = models.Notification(
        user_id=target_user.id,
        message=f"{current_user.full_name or current_user.email} started following you!"
    )
    db.add(new_notif)
    # -------------------------------
    
    db.commit()
    return {"message": f"You are now following {target_user.full_name or target_user.email}"}

@app.delete("/users/{user_id}/follow")
def unfollow_user(
    user_id: int, 
    db: Session = Depends(get_db), 
    current_user: models.User = Depends(utils.get_current_user)
):
    # --- FIX: Adopt the user into this session ---
    current_user = db.merge(current_user)
    # ---------------------------------------------

    target_user = db.query(models.User).filter(models.User.id == user_id).first()
    if not target_user:
        raise HTTPException(status_code=404, detail="User not found")

    if target_user in current_user.following:
        current_user.following.remove(target_user)
        db.commit()
        return {"message": "Unfollowed successfully"}
    
    raise HTTPException(status_code=400, detail="You are not following this user")

# Post a Comment
@app.post("/events/{event_id}/comments", response_model=schemas.CommentOut)
def create_comment(
    event_id: int, 
    comment: schemas.CommentCreate, 
    db: Session = Depends(get_db),
    current_user: models.User = Depends(utils.get_current_user)
):
    # Check if event exists
    event = db.query(models.Event).filter(models.Event.id == event_id).first()
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")
        
    new_comment = models.Comment(
        content=comment.content,
        user_id=current_user.id,
        event_id=event_id
    )
    db.add(new_comment)
    db.commit()
    db.refresh(new_comment)
    return new_comment

# View My Notifications

@app.get("/notifications", response_model=List[schemas.NotificationOut])
def get_notifications(
    db: Session = Depends(get_db),
    current_user: models.User = Depends(utils.get_current_user)
):
    # Get all notifications for me, newest first
    return db.query(models.Notification)\
             .filter(models.Notification.user_id == current_user.id)\
             .order_by(models.Notification.timestamp.desc())\
             .all()

@app.patch("/notifications/{notif_id}/read")
def mark_notification_read(
    notif_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(utils.get_current_user)
):
    notif = db.query(models.Notification).filter(
        models.Notification.id == notif_id,
        models.Notification.user_id == current_user.id
    ).first()
    
    if not notif:
        raise HTTPException(status_code=404, detail="Notification not found")
        
    notif.is_read = True
    db.commit()
    return {"message": "Marked as read"}

# Read Comments for an Event
@app.get("/events/{event_id}/comments", response_model=List[schemas.CommentOut])
def read_comments(event_id: int, db: Session = Depends(get_db)):
    comments = db.query(models.Comment).filter(models.Comment.event_id == event_id).all()
    return comments

@app.get("/admin/stats", response_model=schemas.AdminStats)
def get_admin_stats(
    db: Session = Depends(get_db),
    current_user: models.User = Depends(utils.get_current_user)
):
    # 1. Security Check (Gatekeeper)
    if not current_user.is_staff:
        raise HTTPException(status_code=403, detail="Admin access only")

    # 2. Basic Counts
    total_users = db.query(func.count(models.User.id)).scalar()
    active_users = db.query(func.count(models.User.id)).filter(models.User.is_active == True).scalar()
    total_events = db.query(func.count(models.Event.id)).scalar()
    pending_approvals = db.query(func.count(models.Event.id)).filter(models.Event.is_approved == False).scalar()
    total_comments = db.query(func.count(models.Comment.id)).scalar()

    # 3. Find Most Popular Event (Hardest Query)
    # Logic: Count attendees per event -> Order by Count -> Take Top 1
    # We join Event + Attendees table
    popular_event_id = db.query(
        models.event_attendees.c.event_id,
        func.count(models.event_attendees.c.user_id).label('count')
    ).group_by(models.event_attendees.c.event_id)\
     .order_by(func.count(models.event_attendees.c.user_id).desc())\
     .first()

    popular_event_title = "None"
    if popular_event_id:
        # Fetch the actual title
        event = db.query(models.Event).filter(models.Event.id == popular_event_id.event_id).first()
        if event:
            popular_event_title = f"{event.title} ({popular_event_id.count} attendees)"

    return {
        "total_users": total_users,
        "active_users": active_users,
        "total_events": total_events,
        "pending_approvals": pending_approvals,
        "total_comments": total_comments,
        "most_popular_event": popular_event_title
    }

# --- SCHEDULER LOGIC ---
def check_upcoming_events():
    # 1. Create a new DB session manually (since we are not in a request)
    db = database.SessionLocal()
    try:
        # 2. Find events starting in the next 24 hours (approx)
        now = datetime.datetime.utcnow()
        tomorrow = now + datetime.timedelta(days=1)
        
        # Simple logic: Find events happening roughly tomorrow
        upcoming_events = db.query(models.Event).filter(
            models.Event.date_time >= tomorrow,
            models.Event.date_time < tomorrow + datetime.timedelta(hours=1)
        ).all()
        
        for event in upcoming_events:
            print(f"⏰ REMINDER: {event.title} is happening in 24 hours!")
            # 3. Email all attendees
            for attendee in event.attendees:
                # We use a synchronous version or run async in background
                # For simplicity here, we just print. In prod, call email_utils.
                print(f"   -> Sending email to {attendee.email}")
                
    finally:
        db.close()

# Start the Scheduler when the app starts
scheduler = BackgroundScheduler()
scheduler.add_job(check_upcoming_events, 'interval', hours=1) # Run every hour
scheduler.start()


# Existing Health Check
@app.get("/")
def read_root():
    return {"status": "active", "message": "UBC Connect Backend is running!"}