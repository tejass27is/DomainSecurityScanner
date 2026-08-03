# Scanner Backend
<<<<<<< HEAD
'.
=======

>>>>>>> 95ca74d (invite members to org via email, org-wise history, promo code generateion, redeem code, smtp email added plus some minor changes)
The Scanner Backend is a FastAPI-based service designed to perform domain scanning, store scan results, and generate summarized security scores.
It acts as the core engine that:
Accepts scan requests
Processes domain-related data
Stores results in a database
Provides summarized insights and scores via APIs

 This backend is built with scalability and modularity in mind, making it easy to extend with new scanning features and analytics.

## Deployment

To deploy this project run

```bash
    docker compose up --build
    docker compose up
```


## Project Structure

```bash
Scanner-Backend/
│
├── app/
│   │
│   ├── api/                    # API layer (routes & endpoints)
│   │   ├── auth/               # Authentication-related routes
│   │   │   ├── routes.py
│   │   │   └── controller.py
│   │   │
│   │   ├── scanner/            # Scanner-related routes
│   │   │   ├── routes.py
│   │   │   └── controller.py
│   │   │
│   │   └── ...                 # Other API modules
│   │
│   ├── db/                     # Database configuration & initialization
│   │   ├── base.py             # DB connection/session
│   │   ├── create_db.py        # Database creation logic
│   │   └── init_db.py          # Table initialization
│   │
│   ├── models/                 # SQLAlchemy models
│   │   ├── scan_request.py
│   │   ├── scan_result.py
│   │   ├── scan_summary.py
│   │   └── ...
│   │
│   ├── schemas/                # Pydantic schemas (request/response validation)
│   │   └── ...
│   │
│   ├── services/               # Business logic layer
│   │   └── ...
│   │
│   ├── core/                   # Core configs & utilities
│   │   └── ...
│   │
│   └── main.py                 # FastAPI app entry point
│
├── venv/                       # Virtual environment (ignored in Git)
├── .env                        # Environment variables
├── requirements.txt            # Dependencies
└── README.md
```

What Each Layer Does
🔹 api

    Handles all incoming HTTP requests.

    Defines endpoints (routes)

    Connects routes to controllers
    
    Example: /scan, /get_score/{scan_id}

🔹 controller.py

    Acts as a bridge between routes and business logic.

    Validates request flow

    Calls service functions

    Handles exceptions

🔹 services/

    Contains the core business logic.

    Processes scan data

    Generates results and summaries

    Keeps logic separate from API layer (clean architecture)

🔹 models/

    Defines database tables using SQLAlchemy.

    ScanRequest → Stores scan requests

    ScanResult → Stores raw scan outputs

    ScanSummary → Stores computed scores

🔹 schemas/

    Defines request/response formats using Pydantic.

    Ensures data validation

    Controls API output structure

🔹 db/

    Handles database setup and session management.

    Connection handling

    Table creation

    Dependency injection for DB sessions

🔹 core/

    Stores configuration and reusable utilities.

    Environment variables

    Security configs (JWT, etc.)

🔹 main.py

    Entry point of the application.

    Initializes FastAPI app

    Registers routers

    Adds middleware (e.g., CORS)

    Triggers DB initialization on startup
# redeploy
