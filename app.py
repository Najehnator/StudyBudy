import re
from functools import wraps

import psycopg2
from flask import Flask, flash, g, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)
app.secret_key = "simple-secret-key"


# --------------------------------------------------
# DATABAS
# --------------------------------------------------

def open_database_connection():
    """
    Öppnar en anslutning till PostgreSQL.
    """
    return psycopg2.connect(
        dbname="ar7094",
        user="ar7094",
        password="91mnf6tj",
        host="postgres.mau.se",
        port="55432"
    )


def get_database_connection():
    """
    Hämtar databasanslutningen för den aktuella sidförfrågan.
    """
    if "db_connection" not in g:
        g.db_connection = open_database_connection()
    return g.db_connection


@app.teardown_appcontext
def close_database_connection(error=None):
    """
    Stänger databasanslutningen när sidan är klar.
    """
    connection = g.pop("db_connection", None)
    if connection is not None:
        connection.close()


# --------------------------------------------------
# HJÄLPFUNKTIONER
# --------------------------------------------------

def email_has_valid_format(email_text):
    """
    Kontrollerar om e-postadressen verkar ha rätt format.
    """
    email_pattern = r"^[^@\s]+@[^@\s]+\.[^@\s]+$"
    return re.match(email_pattern, email_text) is not None


def password_is_long_enough(password_text):
    """
    Kontrollerar om lösenordet är minst 8 tecken långt.
    """
    return len(password_text) >= 8


def get_logged_in_user_id():
    """
    Hämtar id för den inloggade användaren från sessionen.
    """
    return session.get("user_id")


def user_is_logged_in():
    """
    Returnerar True om användaren är inloggad.
    """
    return get_logged_in_user_id() is not None


def login_required(view_function):
    """
    Skyddar en route så att bara inloggade användare kommer in.
    """
    @wraps(view_function)
    def wrapped_view(*args, **kwargs):
        if not user_is_logged_in():
            flash("Du måste logga in först.")
            return redirect(url_for("show_login_page"))
        return view_function(*args, **kwargs)
    return wrapped_view


# --------------------------------------------------
# ANVÄNDARE
# --------------------------------------------------

def find_user_by_email(email):
    """
    Hämtar en användare utifrån e-postadress.
    """
    connection = get_database_connection()
    cursor = connection.cursor()
    cursor.execute(
        """
        SELECT id, email, password_hash, display_name
        FROM users
        WHERE email = %s
        """,
        (email,)
    )
    user_row = cursor.fetchone()
    cursor.close()
    return user_row


def create_new_user(email, password):
    """
    Skapar en ny användare i tabellen users.
    """
    connection = get_database_connection()
    cursor = connection.cursor()

    password_hash = generate_password_hash(password)
    display_name = email.split("@")[0]

    cursor.execute(
        """
        INSERT INTO users (email, password_hash, display_name)
        VALUES (%s, %s, %s)
        RETURNING id
        """,
        (email, password_hash, display_name)
    )

    new_user_id = cursor.fetchone()[0]
    connection.commit()
    cursor.close()
    return new_user_id


def get_profile_for_user(user_id):
    """
    Hämtar profilinformation för en användare.
    """
    connection = get_database_connection()
    cursor = connection.cursor()
    cursor.execute(
        """
        SELECT id, email, display_name, campus, subject, study_type,
               availability, competencies, needs, bio
        FROM users
        WHERE id = %s
        """,
        (user_id,)
    )
    profile_row = cursor.fetchone()
    cursor.close()
    return profile_row


# --------------------------------------------------
# ROUTES
# --------------------------------------------------

@app.route("/")
def show_home_page():
    """
    Visar startsidan.
    """
    return render_template("index.html")


@app.route("/register", methods=["GET", "POST"])
def show_register_page():
    """
    Visar registreringssidan och hanterar registrering.
    """
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "").strip()

        if not email or not password:
            flash("Du måste fylla i både e-post och lösenord.")
            return render_template("register.html")

        if not email_has_valid_format(email):
            flash("E-postadressen har inte rätt format.")
            return render_template("register.html")

        if not password_is_long_enough(password):
            flash("Lösenordet måste vara minst 8 tecken långt.")
            return render_template("register.html")

        existing_user = find_user_by_email(email)
        if existing_user:
            flash("Den e-postadressen är redan registrerad.")
            return render_template("register.html")

        create_new_user(email, password)
        flash("Kontot skapades. Du kan nu logga in.")
        return redirect(url_for("show_login_page"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def show_login_page():
    """
    Visar inloggningssidan och hanterar inloggning.
    """
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "").strip()

        user_row = find_user_by_email(email)

        if user_row is None:
            flash("Fel e-post eller lösenord.")
            return render_template("login.html")

        user_id, user_email, stored_password_hash, display_name = user_row

        if not check_password_hash(stored_password_hash, password):
            flash("Fel e-post eller lösenord.")
            return render_template("login.html")

        session["user_id"] = user_id
        flash("Du är nu inloggad.")
        return redirect(url_for("show_dashboard_page"))

    return render_template("login.html")


@app.route("/dashboard")
@login_required
def show_dashboard_page():
    """
    Visar en enkel dashboardsida för inloggad användare.
    """
    user_id = get_logged_in_user_id()
    profile = get_profile_for_user(user_id)
    return render_template("dashboard.html", profile=profile)


@app.route("/logout")
@login_required
def logout_user():
    """
    Loggar ut användaren.
    """
    session.clear()
    flash("Du är nu utloggad.")
    return redirect(url_for("show_home_page"))


if __name__ == "__main__":
    app.run(debug=True)