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
    """
    email_pattern = r"^[^@\s]+@[^@\s]+\.[^@\s]+$"
    return re.match(email_pattern, email_text) is not None


def password_is_long_enough(password_text):
    """
    Kontrollerar om lösenordet är minst 8 tecken långt.
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
    Returnerar True om användaren är inloggad.
    """
    return get_logged_in_user_id() is not None


def login_required(view_function):
    """
    Skyddar routes så att bara inloggade användare kommer in.
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
    Skapar en ny användare.
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

    return bool(
        campus and campus.strip()
        and subject and subject.strip()
        and study_type and study_type.strip()
    )


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
    Uppdaterar användarens profil.
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

    Regel:
    - I vanliga flödet visas inte personer som användaren redan har valt Ja/Nej på.
    - Om användaren söker manuellt ska även tidigare valda personer kunna dyka upp igen.
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
    """

    query_values = [current_user_id, current_user_id]

    # Om användaren INTE söker manuellt:
    # dölj personer som användaren redan har valt Ja/Nej på.
    if not search_query:
        sql_query += """
          AND NOT EXISTS (
              SELECT 1
              FROM interests
              WHERE interests.from_user_id = %s
                AND interests.to_user_id = other_user.id
          )
        """
        query_values.append(current_user_id)

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
    Sparar om användaren är intresserad eller inte.

    Om användaren redan har gjort ett val tidigare uppdateras valet.
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
    Kontrollerar om den andra användaren redan har visat intresse.
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


def get_my_confirmed_matches(current_user_id):
    """
    Hämtar alla bekräftade matchningar för den inloggade användaren.
    """
    connection = get_database_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT
            matches.id,
            other_user.id,
            other_user.display_name,
            other_user.email,
            other_user.campus,
            other_user.subject,
            other_user.study_type,
            other_user.availability,
            other_user.competencies,
            other_user.needs,
            other_user.bio,
            other_user.profile_image,
            matches.created_at
        FROM matches
        JOIN users AS other_user
            ON (
                (matches.user_a_id = %s AND matches.user_b_id = other_user.id)
                OR
                (matches.user_b_id = %s AND matches.user_a_id = other_user.id)
            )
        ORDER BY matches.created_at DESC
        """,
        (current_user_id, current_user_id)
    )

    rows = cursor.fetchall()
    cursor.close()

    return rows


def get_users_who_liked_me(current_user_id):
    """
    Hämtar personer som har visat intresse för mig,
    men som jag ännu inte har svarat på.

    Om jag redan har tryckt ja eller nej på personen visas den inte i hjärt-dropdownen.
    Personen kan fortfarande hittas via sök/matchningar.
    """
    connection = get_database_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT
            users.id,
            users.display_name,
            users.campus,
            users.subject,
            users.profile_image
        FROM interests
        JOIN users
            ON interests.from_user_id = users.id
        WHERE interests.to_user_id = %s
          AND interests.is_interested = TRUE
          AND NOT EXISTS (
              SELECT 1
              FROM interests AS my_interest
              WHERE my_interest.from_user_id = %s
                AND my_interest.to_user_id = users.id
          )
        ORDER BY interests.created_at DESC
        """,
        (current_user_id, current_user_id)
    )

    rows = cursor.fetchall()
    cursor.close()

    return rows


@app.context_processor
def inject_likes_dropdown():
    """
    Gör liked_me_users tillgänglig i alla templates.
    """
    if user_is_logged_in():
        liked_me_users = get_users_who_liked_me(get_logged_in_user_id())
        return {"liked_me_users": liked_me_users}

    return {"liked_me_users": []}


# --------------------------------------------------
# CHATT
# --------------------------------------------------

def get_match_for_user(match_id, current_user_id):
    """
    Hämtar en match om den inloggade användaren är en del av matchningen.
    """
    connection = get_database_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT
            matches.id,
            matches.user_a_id,
            matches.user_b_id,
            other_user.display_name
        FROM matches
        JOIN users AS other_user
            ON (
                (matches.user_a_id = %s AND matches.user_b_id = other_user.id)
                OR
                (matches.user_b_id = %s AND matches.user_a_id = other_user.id)
            )
        WHERE matches.id = %s
          AND (%s = matches.user_a_id OR %s = matches.user_b_id)
        """,
        (current_user_id, current_user_id, match_id, current_user_id, current_user_id)
    )

    match_row = cursor.fetchone()
    cursor.close()

    return match_row


def get_messages_for_match(match_id):
    """
    Hämtar alla meddelanden för en viss match.
    """
    connection = get_database_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT
            messages.id,
            messages.sender_user_id,
            users.display_name,
            messages.message_text,
            messages.created_at
        FROM messages
        JOIN users
            ON messages.sender_user_id = users.id
        WHERE messages.match_id = %s
        ORDER BY messages.created_at ASC
        """,
        (match_id,)
    )

    rows = cursor.fetchall()
    cursor.close()

    return rows


def save_message(match_id, sender_user_id, message_text):
    """
    Sparar ett nytt chattmeddelande.
    """
    connection = get_database_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        INSERT INTO messages (match_id, sender_user_id, message_text)
        VALUES (%s, %s, %s)
        """,
        (match_id, sender_user_id, message_text)
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

        except Exception as error:
            print("Fel vid registrering:", error)

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

        except Exception as error:
            print("Fel vid profiluppdatering:", error)

            connection = g.pop("db_connection", None)

            if connection is not None:
                connection.rollback()
                connection.close()

            flash("Något gick fel när profilen skulle uppdateras.", "error")
            profile = get_profile_for_user(user_id)
            return render_template("profile.html", profile=profile)

    profile = get_profile_for_user(user_id)

    return render_template("profile.html", profile=profile)


@app.route("/user/<int:user_id>")
@login_required
def show_other_user_profile_page(user_id):
    """
    Visar en annan användares profil.
    Används från likes-dropdownen.
    """
    current_user_id = get_logged_in_user_id()

    if current_user_id == user_id:
        return redirect(url_for("show_profile_page"))

    profile = get_profile_for_user(user_id)

    if profile is None:
        flash("Användaren hittades inte.", "error")
        return redirect(url_for("show_dashboard_page"))

    return render_template("other_user_profile.html", profile=profile)


@app.route("/matches")
@login_required
def show_matches_page():
    """
    Visar möjliga matchningar, sökning och filtrering.
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
    Hanterar ja/nej-intresse för en annan användare.
    """
    current_user_id = get_logged_in_user_id()

    if current_user_id == to_user_id:
        flash("Du kan inte swipa på dig själv.", "error")
        return redirect(request.referrer or url_for("show_matches_page"))

    if action not in ["like", "dislike"]:
        flash("Ogiltig swipe-handling.", "error")
        return redirect(request.referrer or url_for("show_matches_page"))

    is_interested = action == "like"

    try:
        save_user_interest(current_user_id, to_user_id, is_interested)

        if is_interested and other_user_is_interested_in_me(to_user_id, current_user_id):
            create_match_if_not_exists(current_user_id, to_user_id)
            flash("Det blev en matchning!", "success")
            return redirect(url_for("show_my_matches_page"))

        if is_interested:
            flash("Du visade intresse.", "success")
        else:
            flash("Du valde att inte visa intresse.", "success")

    except Exception as error:
        print("Fel vid swipe:", error)

        connection = g.pop("db_connection", None)

        if connection is not None:
            connection.rollback()
            connection.close()

        flash("Något gick fel när ditt val skulle sparas.", "error")

    return redirect(request.referrer or url_for("show_matches_page"))


@app.route("/my-matches")
@login_required
def show_my_matches_page():
    """
    Visar alla bekräftade matchningar för den inloggade användaren.
    """
    user_id = get_logged_in_user_id()
    my_matches = get_my_confirmed_matches(user_id)

    return render_template("my_matches.html", my_matches=my_matches)


@app.route("/chat/<int:match_id>", methods=["GET", "POST"])
@login_required
def show_chat_page(match_id):
    """
    Visar och hanterar chatt för en bekräftad matchning.
    """
    current_user_id = get_logged_in_user_id()

    match_row = get_match_for_user(match_id, current_user_id)

    if match_row is None:
        flash("Du har inte tillgång till den här chatten.", "error")
        return redirect(url_for("show_my_matches_page"))

    if request.method == "POST":
        message_text = request.form.get("message_text", "").strip()

        if not message_text:
            flash("Du kan inte skicka ett tomt meddelande.", "error")
            return redirect(url_for("show_chat_page", match_id=match_id))

        try:
            save_message(match_id, current_user_id, message_text)
            return redirect(url_for("show_chat_page", match_id=match_id))

        except Exception as error:
            print("Fel vid skickande av meddelande:", error)

            connection = g.pop("db_connection", None)

            if connection is not None:
                connection.rollback()
                connection.close()

            flash("Något gick fel när meddelandet skulle skickas.", "error")
            return redirect(url_for("show_chat_page", match_id=match_id))

    chat_messages = get_messages_for_match(match_id)

    return render_template(
        "chat.html",
        match_row=match_row,
        chat_messages=chat_messages,
        current_user_id=current_user_id
    )


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