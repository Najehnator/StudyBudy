import os
import re
from functools import wraps

import psycopg2
from dotenv import load_dotenv
from flask import Flask, flash, g, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

load_dotenv()

db_name = os.environ.get("DB_NAME") or os.environ.get("dbname")
db_user = os.environ.get("DB_USER") or os.environ.get("user")
db_password = os.environ.get("DB_PASSWORD") or os.environ.get("password")
db_host = os.environ.get("DB_HOST") or os.environ.get("host")
db_port = os.environ.get("DB_PORT") or os.environ.get("port")

app = Flask(__name__)
app.secret_key = "simple-secret-key"

UPLOAD_FOLDER = "static/uploads"
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)


# --------------------------------------------------
# DATABAS
# --------------------------------------------------

def open_database_connection():
    """
    Öppnar en anslutning till PostgreSQL.

    Kravkoppling:
    - Q-TEK-2: Systemet ska använda en databas för lagring av användardata.
    """
    return psycopg2.connect(
        dbname=db_name,
        user=db_user,
        password=db_password,
        host=db_host,
        port=db_port
    )


def get_database_connection():
    """
    Hämtar databasanslutningen för den aktuella sidförfrågan.

    Om ingen anslutning finns för den här förfrågan öppnas en ny.
    """
    if "db_connection" not in g:
        g.db_connection = open_database_connection()
    return g.db_connection


@app.teardown_appcontext
def close_database_connection(error=None):
    """
    Stänger databasanslutningen när sidförfrågan är klar.
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

    Kravkoppling:
    - F-ANV-1.3: Systemet ska kontrollera att e-postadressen har korrekt format.
    """
    email_pattern = r"^[^@\s]+@[^@\s]+\.[^@\s]+$"
    return re.match(email_pattern, email_text) is not None


def password_is_long_enough(password_text):
    """
    Kontrollerar om lösenordet är minst 8 tecken långt.

    Kravkoppling:
    - F-ANV-1.4: Systemet ska kontrollera att lösenordet uppfyller säkerhetskrav.
    """
    return len(password_text) >= 8

def allowed_file(filename):
    """
    Kontrollerar om filen har en tillåten filändelse.
    """
    allowed_extensions = {"png", "jpg", "jpeg"}
    return "." in filename and filename.rsplit(".", 1)[1].lower() in allowed_extensions


def get_logged_in_user_id():
    """
    Hämtar id för den inloggade användaren från sessionen.
    """
    return session.get("user_id")


def user_is_logged_in():
    """
    Returnerar True om användaren är inloggad, annars False.
    """
    return get_logged_in_user_id() is not None


def login_required(view_function):
    """
    Skyddar en route så att bara inloggade användare kommer in.

    Kravkoppling:
    - Q-SÄK-1: Systemet ska kräva inloggning för användarspecifika funktioner.
    - Q-SÄK-3: Systemet ska säkerställa att användare bara kommer åt sin egen data.
    """
    @wraps(view_function)
    def wrapped_view(*args, **kwargs):
        if not user_is_logged_in():
            flash("Du måste logga in först.", "error")
            return redirect(url_for("show_login_page"))
        return view_function(*args, **kwargs)
    return wrapped_view


# --------------------------------------------------
# ANVÄNDARE
# --------------------------------------------------

def find_user_by_email(email):
    """
    Hämtar en användare utifrån e-postadress.

    Kravkoppling:
    - F-ANV-1.1: Systemet ska kräva en unik e-postadress vid registrering.
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

    Kravkoppling:
    - F-ANV-1: Systemet ska tillåta användare att skapa konto.
    - F-ANV-1.2: Systemet ska kräva lösenord vid registrering.
    - Q-SÄK-2: Lösenord ska lagras i skyddad form.
    """
    connection = get_database_connection()
    cursor = connection.cursor()

    password_hash = generate_password_hash(password, method="pbkdf2:sha256")
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

    Kravkoppling:
    - F-ANV-2: Systemet ska tillåta användare att skapa och uppdatera en profil.
    """
    connection = get_database_connection()
    cursor = connection.cursor()
    cursor.execute(
        """
        SELECT id, email, display_name, campus, subject, study_type,
               availability, competencies, needs, bio, profile_image
        FROM users
        WHERE id = %s
        """,
        (user_id,)
    )
    profile_row = cursor.fetchone()
    cursor.close()
    return profile_row

def profile_is_complete(profile):
    """
    Kontrollerar om profilen har tillräcklig information för matchning.
    """
    if not profile:
        return False

    campus = profile[3]
    subject = profile[4]
    study_type = profile[5]

    return bool(campus and campus.strip() and subject and subject.strip() and study_type and study_type.strip())


def update_user_profile(
    user_id,
    display_name,
    campus,
    subject,
    study_type,
    availability,
    competencies,
    needs,
    bio,
    profile_image
):
    """
    Uppdaterar profilinformation för den inloggade användaren.

    Kravkoppling:
    - F-ANV-2: Profilhantering.
    - F-ANV-2.1: Användaren ska kunna ange studieinformation.
    - F-ANV-2.2: Användaren ska kunna ange kompetenser.
    - Q-SÄK-3: Endast den inloggade användarens profil uppdateras.
    """
    connection = get_database_connection()
    cursor = connection.cursor()

    if profile_image:
        cursor.execute(
            """
            UPDATE users
            SET display_name = %s,
                campus = %s,
                subject = %s,
                study_type = %s,
                availability = %s,
                competencies = %s,
                needs = %s,
                bio = %s,
                profile_image = %s,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = %s
            """,
            (
                display_name,
                campus,
                subject,
                study_type,
                availability,
                competencies,
                needs,
                bio,
                profile_image,
                user_id
            )
        )
    else:
        cursor.execute(
            """
            UPDATE users
            SET display_name = %s,
                campus = %s,
                subject = %s,
                study_type = %s,
                availability = %s,
                competencies = %s,
                needs = %s,
                bio = %s,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = %s
            """,
            (
                display_name,
                campus,
                subject,
                study_type,
                availability,
                competencies,
                needs,
                bio,
                user_id
            )
        )

    connection.commit()
    cursor.close()


# --------------------------------------------------
# MATCHNING
# --------------------------------------------------

def get_possible_matches_for_user(current_user_id, campus_filter="", subject_filter="", search_query=""):
    """
    Hämtar möjliga studiekamrater för den inloggade användaren.

    Matchningen hålls enkel:
    - samma ämne ger poäng
    - samma campus ger poäng
    - samma studietyp ger poäng
    - om den andres kompetenser matchar mina behov ger det poäng
    - om mina kompetenser matchar den andres behov ger det poäng

    Kravkoppling:
    - F-MAT-1: Systemet ska matcha användare baserat på behov och kompetenser.
    - F-MAT-1.1: Systemet ska möjliggöra filtrering efter campus.
    - F-MAT-1.2: Systemet ska möjliggöra filtrering efter ämne.
    - F-INT-1: Systemet ska tillåta användare att markera intresse eller ej intresse.
    """
    connection = get_database_connection()
    cursor = connection.cursor()

    sql_query = """
        SELECT
            other_user.id,
            other_user.display_name,
            other_user.campus,
            other_user.subject,
            other_user.study_type,
            other_user.availability,
            other_user.competencies,
            other_user.needs,
            other_user.bio,
            other_user.profile_image,
            (
                CASE
                    WHEN my_user.subject IS NOT NULL
                     AND other_user.subject IS NOT NULL
                     AND my_user.subject = other_user.subject
                    THEN 1 ELSE 0
                END
                +
                CASE
                    WHEN my_user.campus IS NOT NULL
                     AND other_user.campus IS NOT NULL
                     AND my_user.campus = other_user.campus
                    THEN 1 ELSE 0
                END
                +
                CASE
                    WHEN my_user.study_type IS NOT NULL
                     AND other_user.study_type IS NOT NULL
                     AND my_user.study_type = other_user.study_type
                    THEN 1 ELSE 0
                END
                +
                CASE
                    WHEN my_user.needs IS NOT NULL
                     AND my_user.needs <> ''
                     AND other_user.competencies IS NOT NULL
                     AND other_user.competencies ILIKE '%%' || my_user.needs || '%%'
                    THEN 1 ELSE 0
                END
                +
                CASE
                    WHEN other_user.needs IS NOT NULL
                     AND other_user.needs <> ''
                     AND my_user.competencies IS NOT NULL
                     AND my_user.competencies ILIKE '%%' || other_user.needs || '%%'
                    THEN 1 ELSE 0
                END
            ) AS match_score
        FROM users AS my_user
        JOIN users AS other_user
            ON my_user.id <> other_user.id
        WHERE my_user.id = %s
          AND other_user.id <> %s

          -- Visa inte personer som jag redan har swipat på
          AND NOT EXISTS (
              SELECT 1
              FROM interests
              WHERE interests.from_user_id = %s
                AND interests.to_user_id = other_user.id
          )
    """

    query_values = [current_user_id, current_user_id, current_user_id]

    if campus_filter:
        sql_query += " AND other_user.campus ILIKE %s"
        query_values.append(f"%{campus_filter}%")

    if subject_filter:
        sql_query += " AND other_user.subject ILIKE %s"
        query_values.append(f"%{subject_filter}%")

    if search_query:
        sql_query += """
            AND (
                other_user.display_name ILIKE %s
                OR other_user.campus ILIKE %s
                OR other_user.subject ILIKE %s
                OR other_user.study_type ILIKE %s
                OR other_user.competencies ILIKE %s
                OR other_user.needs ILIKE %s
                OR other_user.bio ILIKE %s
            )
        """
        search_value = f"%{search_query}%"
        query_values.extend([
            search_value,
            search_value,
            search_value,
            search_value,
            search_value,
            search_value,
            search_value
        ])

    sql_query += """
        ORDER BY match_score DESC,
                 other_user.display_name ASC
    """

    cursor.execute(sql_query, tuple(query_values))
    rows = cursor.fetchall()
    cursor.close()

    return rows

def save_user_interest(from_user_id, to_user_id, is_interested):
    """
    Sparar om den inloggade användaren är intresserad eller inte intresserad
    av en annan användare.

    Kravkoppling:
    - F-INT-1: Systemet ska tillåta användare att markera intresse eller ej intresse.
    """
    connection = get_database_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        INSERT INTO interests (from_user_id, to_user_id, is_interested)
        VALUES (%s, %s, %s)
        ON CONFLICT (from_user_id, to_user_id)
        DO UPDATE SET
            is_interested = EXCLUDED.is_interested,
            updated_at = CURRENT_TIMESTAMP
        """,
        (from_user_id, to_user_id, is_interested)
    )

    connection.commit()
    cursor.close()


def other_user_is_interested_in_me(other_user_id, current_user_id):
    """
    Kontrollerar om den andra användaren redan har visat intresse
    för den inloggade användaren.

    Kravkoppling:
    - F-INT-1.1: Matchning vid ömsesidigt intresse.
    """
    connection = get_database_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT id
        FROM interests
        WHERE from_user_id = %s
          AND to_user_id = %s
          AND is_interested = TRUE
        """,
        (other_user_id, current_user_id)
    )

    interest_row = cursor.fetchone()
    cursor.close()

    return interest_row is not None

def create_match_if_not_exists(user_a_id, user_b_id):
    """
    Skapar en match mellan två användare om den inte redan finns.

    För att undvika dubbletter sparas alltid lägsta id först.
    Exempel:
    user_a_id = 2, user_b_id = 5
    sparas som:
    user_a_id = 2, user_b_id = 5

    user_a_id = 5, user_b_id = 2
    sparas också som:
    user_a_id = 2, user_b_id = 5

        Kravkoppling:
    - F-INT-1.1: Systemet ska skapa en match när två användare har visat ömsesidigt intresse.
    """
    first_user_id = min(user_a_id, user_b_id)
    second_user_id = max(user_a_id, user_b_id)

    connection = get_database_connection()
    cursor = connection.cursor()

    cursor.execute(
    """
    INSERT INTO matches (user_a_id, user_b_id)
    VALUES (%s, %s)
    ON CONFLICT (user_a_id, user_b_id)
    DO NOTHING
    """,
    (first_user_id, second_user_id)
    )

    connection.commit()
    cursor.close()
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

    Kravkoppling:
    - F-ANV-1 till F-ANV-1.5
    """
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "").strip()

        if not email or not password:
            flash("Du måste fylla i både e-post och lösenord.", "error")
            return render_template("register.html")

        if not email_has_valid_format(email):
            flash("E-postadressen har inte rätt format.", "error")
            return render_template("register.html")

        if not password_is_long_enough(password):
            flash("Lösenordet måste vara minst 8 tecken långt.", "error")
            return render_template("register.html")

        existing_user = find_user_by_email(email)
        if existing_user:
            flash("Den e-postadressen är redan registrerad.", "error")
            return render_template("register.html")

        try:
            create_new_user(email, password)
            flash("Kontot skapades. Du kan nu logga in.", "success")
            return redirect(url_for("show_login_page"))
        except Exception:
            connection = g.pop("db_connection", None)
            if connection is not None:
                connection.rollback()
                connection.close()

            flash("Något gick fel när kontot skulle skapas.", "error")
            return render_template("register.html")

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def show_login_page():
    """
    Visar inloggningssidan och hanterar inloggning.

    Kravkoppling:
    - Q-SÄK-1: Inloggning krävs för användarspecifika funktioner.
    """
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "").strip()

        user_row = find_user_by_email(email)

        if user_row is None:
            flash("Fel e-post eller lösenord.", "error")
            return render_template("login.html")

        user_id, user_email, stored_password_hash, display_name = user_row

        if not check_password_hash(stored_password_hash, password):
            flash("Fel e-post eller lösenord.", "error")
            return render_template("login.html")

        session["user_id"] = user_id
        flash("Du är nu inloggad.", "success")
        return redirect(url_for("show_dashboard_page"))

    return render_template("login.html")


@app.route("/dashboard")
@login_required
def show_dashboard_page():
    """
    Visar dashboard för inloggad användare.
    """
    user_id = get_logged_in_user_id()
    profile = get_profile_for_user(user_id)
    return render_template("dashboard.html", profile=profile)


@app.route("/profile", methods=["GET", "POST"])
@login_required
def show_profile_page():
    """
    Visar och uppdaterar användarens profil.

    Kravkoppling:
    - F-ANV-2
    - F-ANV-2.1
    - F-ANV-2.2
    """
    user_id = get_logged_in_user_id()

    if request.method == "POST":
        display_name = request.form.get("display_name", "").strip()
        campus = request.form.get("campus", "").strip()
        subject = request.form.get("subject", "").strip()
        study_type = request.form.get("study_type", "").strip()
        availability = request.form.get("availability", "").strip()
        competencies = request.form.get("competencies", "").strip()
        needs = request.form.get("needs", "").strip()
        bio = request.form.get("bio", "").strip()

        if not display_name:
            flash("Du måste fylla i namn.", "error")
            profile = get_profile_for_user(user_id)
            return render_template("profile.html", profile=profile)

        image_file = request.files.get("profile_image")
        image_filename = None

        if image_file and image_file.filename:
            if not allowed_file(image_file.filename):
                flash("Du får bara ladda upp JPG- eller PNG-bilder.", "error")
                profile = get_profile_for_user(user_id)
                return render_template("profile.html", profile=profile)

            safe_filename = secure_filename(image_file.filename)
            image_filename = str(user_id) + "_" + safe_filename
            image_path = os.path.join(app.config["UPLOAD_FOLDER"], image_filename)
            image_file.save(image_path)

        try:
            update_user_profile(
                user_id,
                display_name,
                campus,
                subject,
                study_type,
                availability,
                competencies,
                needs,
                bio,
                image_filename
            )

            flash("Profilen uppdaterades.", "success")
            return redirect(url_for("show_dashboard_page"))

        except Exception:
            connection = g.pop("db_connection", None)
            if connection is not None:
                connection.rollback()
                connection.close()

            flash("Något gick fel när profilen skulle uppdateras.", "error")
            profile = get_profile_for_user(user_id)
            return render_template("profile.html", profile=profile)
     #GET-request
    profile = get_profile_for_user(user_id)
    return render_template("profile.html", profile=profile)

@app.route("/matches")
@login_required
def show_matches_page():
    """
    Visar möjliga matchningar, sökning och filtrering.

    Kravkoppling:
    - F-MAT-1
    - F-MAT-1.1
    - F-MAT-1.2
    - F-INT-1
    """
    user_id = get_logged_in_user_id()

    campus_filter = request.args.get("campus", "").strip()
    subject_filter = request.args.get("subject", "").strip()
    search_query = request.args.get("search", "").strip()

    matches = get_possible_matches_for_user(
        user_id,
        campus_filter,
        subject_filter,
        search_query
    )

    return render_template(
        "matches.html",
        matches=matches,
        campus_filter=campus_filter,
        subject_filter=subject_filter,
        search_query=search_query
    )


@app.route("/swipe/<int:to_user_id>/<string:action>", methods=["POST"])
@login_required
def handle_swipe(to_user_id, action):
    """
    Hanterar swipe/intresse för en annan användare.

    action kan vara:
    - like
    - dislike

    Kravkoppling:
    - F-INT-1: Visa intresse eller ej intresse.
    - F-INT-1.1: Matchning vid ömsesidigt intresse.
    """
    current_user_id = get_logged_in_user_id()

    if current_user_id == to_user_id:
        flash("Du kan inte swipa på dig själv.", "error")
        return redirect(url_for("show_matches_page"))

    if action not in ["like", "dislike"]:
        flash("Ogiltig swipe-handling.", "error")
        return redirect(url_for("show_matches_page"))

    is_interested = action == "like"

    try:
        save_user_interest(current_user_id, to_user_id, is_interested)

        if is_interested and other_user_is_interested_in_me(to_user_id, current_user_id):
            create_match_if_not_exists(current_user_id, to_user_id)
            flash("Det blev en matchning!", "success")
        elif is_interested:
            flash("Du visade intresse.", "success")
        else:
            flash("Du valde att inte visa intresse.", "success")

    except Exception:
        connection = g.pop("db_connection", None)
        if connection is not None:
            connection.rollback()
            connection.close()

        flash("Något gick fel när ditt val skulle sparas.", "error")

    return redirect(url_for("show_matches_page"))

@app.route("/logout")
@login_required
def logout_user():
    """
    Loggar ut användaren.
    """
    session.clear()
    flash("Du är nu utloggad.", "success")
    return redirect(url_for("show_home_page"))


if __name__ == "__main__":
    app.run(debug=True, port=5050)