# Permitting App
#### Video Demo: https://youtu.be/geE2Gtrdst4
#### Description:
##### In summary
***Permitting*** is a web application, meant to cover the lifecycle of safety permits on an industrial site.
The status flows & business rules are based on a generalized version of the legislation applied in Bulgaria.
##### Tech stack
The app was developed using the following technologies:
- **for the back-end**: the `Python` framework `Django`, used together with `SQLite` for the database;
- **for the front-end**: the `Bootstrap` framework for the styles, and some plain `JavaScript` for some of the interactive features.
#### Distinctiveness and Complexity
The basic premise of the ***Permitting*** app differs from all the other projects in the course. As stated in the short description above, it is *" meant to cover the lifecycle of safety permits"*. That is to say, it needs to provide the facilities for creating a permit, and following over it's authorization, daily opening & closing, and finalization.
So the uderlying business process is very different than that of an online encyplopedia, an e-commerce site, an e-mail client or a social network.

While it does use the same techniques as the course's projects, the scale of ***Permitting*** is orders of magnitude larger. It consists of about 20 models in order to represent all the needed entities in the database.

Back to the issue of process complexity - in order to narrow down scope to a size that is manageble for a final project, I based the app on a generalized version of the safety permitting legislation applied in Bulgaria. There are actually at least two distinct processes when it comes to issuing safety permits - one when work is being done on electrical systems, and another one when a non-electrical equipment is being worked on. Even after the generalization, the process still has 7 distinct roles, each of which has their own responsibilities & actions they can perform. Each user can be assigned more than one role.

While tracking of state was necessary in the course's projects (like tracking if an email is read, or if a post is liked, or a user is followed), the permitting process is far more demanding. In the framework of the app, a permit can go through 13 statuses.

The multitude of roles and statuses outlined above makes it so that even experienced users may be confused at times as to who has to take what action next. This makes implementing some form of in-app notifications essential. Again, this is something that wasn't such a necessity in the course's projects.

In the ***Permitting*** app, the concept of notifications is implemented with an abstract base class, and two separate classes that inherit from it - one for Action Notifications (notifications that the user must perform some task), and one for Info Notifications (as the name implies - these are purely for informational purposes, and the user has the ability to dismiss them). Admittedly, the notifications don't use `WebSockets` or any such approach, so displaying the most recent ones requires a page reload.

The ***Permitting*** app also has a concept of version control. This is achieved through the `Contribution` model. Every entry stores references to the author, the version date, the associated permit, and the JSON serialized total content of that permit. Though the app currently only has the functionality to display just the latest version, the idea is to have an audit trail that the admin can inspect, if it's ever required to determine who made any change or confirmation on the permit.
#### Listing of the project's files & folders
- `capstone/` - Project directory/project package. Contains regular project files `asgi.py`,  `__init__.py`,  `settings.py`,  `urls.py`,  `wsgi.py`.
- `db.sqlite3`- The app's database.
- `manage.py` - Management utility.
- `permitting/` - App directory. Contains regular app files `admin.py`, `apps.py`, `__init__.py`, `models.py `, `tests.py`, `urls.py`, `views.py`, but also:
    - `custom_forms.py` - Contains Django forms that are used in several of the app's routes.
    - `helpers_general.py` - Contains several helper-functions that are usually used in more than one of the app's routes.
    - `migrations/` - Migrations directory. Contains a `__init__.py` file, and separate files for each migration that was performed.
    - `static/permitting/` - Static files directory. Contains:
        - `helpers.js` - Contains several helper-functions (for rendering paginated items, dismissing notifications and such) that are usually imported in more than one of the individual templates' `.js` files.
        - `index.js` - Dynamic functionality (dismissing notifications) for the Index page.
        - `issue-new.js` - Dynamic functionality (when an equipment entry is selected, auto selects the area related risks and required personal protection, based on the equipment's area property) for the Issue New Permit page.
        - `login.js` - Dynamic functionality (resizing of form, based on viewport size) for the Login page.
        - `my_permits.js` - Dynamic functionality (get & render paginated permits) for the My Permits page.
        - `notifications.js` - Dynamic functionality (get & render paginated notifications) for the Notifications page.
        - `styles.css` - Styling, applicable to all pages.
    - `templates/permitting/` - Templates directory. Contains:
        - `404.html` - Template for a basic 404 page.
        - `add-loto.html` - Template for Add Lockout & Tagout page, where a user with `loto_officer` role confirms to have applied Lockout & Tagout.
        - `apply-for-finalization.html` - Template for Apply For Finalization page where a user with `task_responsible` role submits the permit for review before finalization.
        - `authorize-permit.html` - Template for Authorize page - allows a user with `authorizer` role to either authorize a permit (releasing it for application of Lockout & Tagout), or reject it (ending the flow for this permit).
        - `close-for-workday.html` - Template for Close For Workday page, where first a user with `foreman` role confirms to have led the workers out of the work area, and then a user with `safety_gatekeeper` role verifies.
        - `confirm-debriefing.html` - Template for Confirm Debriefing page where users with `worker` role confirm to have been debriefed both on the area & equipment related risks, and the task-specific hazards for the work they're about to perform.
        - `display-permit.html` - Template that displays the latest version of a permit.
        - `enter-staff-for-permit.html` - Template for Enter Staff page where a user with `task_responsible` role selects a user with role `foreman` and one or more users with role `worker` to be on the team for the permit.
        - `index.html` - Template for the Index page.
        - `issue-new.html` - Template for Issue New Permit page that allows a user with `issuer` role to create a new permit.
        - `layout.html` - Template specifying the common layout for the other templates.
        - `login.html` - Template for the Login page.
        - `my-permits.html` - Template for My Permits page which shows a paginated list of active (or inactive) permits, associated with the logged in user.
        - `notifications.html` - Template for Notifications page which shows a paginated list of Action or Info notifications, associated with the logged in user.
        - `open-for-workday.html` - Template for Open For Workday page, where first a user with `safety_gatekeeper` role confirms that the safety measures are in place, and then a user with `foreman` role confirms to have led the workers into the work area.
        - `remove-loto.html` - Template for Remove Lockout & Tagout page, where first a user with `loto_officer` role confirms to have removed Lockout & Tagout, and then a user with `safety_gatekeeper` role verifies. After the actions of both are completed, the permit gets finalized.
        - `review-finalization-application.html` - Template for Review Finalization Application page where a user with `authorizer` role can review a permit that has been applied for finalization, and either refuse to finalize now (thus returning it to the `task_responsible`), send the permit for Lockout & Tagout removal, or finalize the permit, while keeping Lockout & Tagout in place.
        - `safety-gk.html` - Template for Safety Gatekeeping page where a user with `safety_gatekeeper` role confirms to have personally checked the Lockout & Tagout procedures are applied, as specified in the permit.
        - `task-instruction.html` - Template for Task Instruction page where a user with `task_responsible` role confirms to have instructed the whole worker team on the task-specific risks.
    - `templatetags/` - Directory for custom filters. Contains a `__init__.py` file, and `custom_filters.py`, where custom filters for rendering certain data are defined.

- `README.md` - File you're reading.

#### How to run the ***Permitting*** app
Running the app is as simple as running `$ python manage.py runserver`. It doesn't require installation of any additional packages, hence there is no `requirements.txt` file.

The app is meant to be used only by users that have an account, so a user that is not logged in can only use the login page.

I've created several users for the purpose of developing and demonstrating the app. Here are some:

| Username | Eligible for role | Org |
|----------|-------------------|-----|
| issuer | issuer | - |
| authorizer | authorizer | - |
| loto_officer | loto_officer | - |
| safety_gatekeeper | safety_gatekeeper | - |
| tr_123fs | task_responsible | 123 Facility Solutions |
| f_123fs | foreman | 123 Facility Solutions |
| w1_123fs | worker | 123 Facility Solutions |
| w2_123fs | worker | 123 Facility Solutions |
| w3_123fs | worker | 123 Facility Solutions |

The usernames roughly correspond to the roles, that you'll see further into the README. Since this is not a production deployment, and for easier switching between accounts to test the features, all the above users have a password of `0000`.

#### The permitting process
Below is an outline of the process that the app is based on:
- There is a need for work to be done with a safety permit (usually every company or institution has a list of tasks that require a permit).
- The `Issuer` formulates a description of the task, and determines:
    - The equipment that will be worked on.
    - The personal and collective protection equipment.
    - The safety measures (Lockout & Tagout).
    - The person who will be appointed as `Task Responsible` for the permit.
- The `Task Responsible` determites the people to be appointed as `Workers` and a `Foreman`.
- The `Authorizer` reviews the new permit, and can either authorize it (there by appointing a `LOTO Officer` and a `Safety Gatekeeper`, and releasing the permit for application of Lockout & Tagout), or reject it (ending the flow for this permit).
- The `LOTO Officer` applies the required Lockout & Tagout.
- The `Safety Gatekeeper` verifies that Lockout & Tagout is correctly applied, demonstrates it in action to the team, and debriefs them on the area-specific hazards.
- The `Task Responsible` debriefs the team on task-specific hazards.
- The `Workers` acknowledge both debfriefings.
- Now the permit needs to be opened for the day. This is needed every time a new permit is created, and for every day work is going to be performed on an existing permit.
- The `Safety Gatekeeper` confirms that the work area & equipment are ready for the workers to be led in.
- The `Foreman` confirms to have led all the workers in the work area.
- Once work for the day is finished, the `Foreman` confirms to have led all the workers out of the work area.
- The `Safety Gatekeeper` verifies that all workers have been led out of the work area.
- Now that the permit is closed for the day, it may either be re-opened (repeating the procedure), or be applied for finalization.
- When the task is completed and the permit is closed for the day, the `Task Responsible` applies for finalization of the permit, confirming:
    - The equipment that was worked on can safely be put into operation or reserve, or is secured while waiting for further works.
    - The work area has been cleaned up.
    - The workers have been led out of the work area.
- The `Authorizer` reviews the permit, and either:
    - Refuses to finalize now (thus returning it to the `Task Responsible`), or;
    - Finalizes the permit, while keeping Lockout & Tagout in place, or;
    - Sends the permit for Lockout & Tagout removal:
        - The `LOTO Officer` confirms to have removed the Lockout & Tagout (LOTO) procedures.
        - The `Safety Gatekeeper` verifies that the Lockout & Tagout (LOTO) has been removed, and the permit is finalized.
#### User roles
Here's a list of all roles:
- `issuer`
- `task_responsible`
- `authorizer`
- `loto_officer`
- `safety_gatekeeper`
- `foreman`
- `worker`

They correspond with the ones in the process outline above.

A user can have multiple roles. Assignment of roles:
1. The roles that a user *can have* are set by the admin as entries in the `eligible_for_roles` many-to-many field for each user entry.
2. The roles that a user *does have* for each specific permit are set:
    - for `worker`: as entries in the `WorkerTeams` table.
    - for all other roles: as entries in the `Appointments` table.
#### Permit statuses
To track progress of each permit, the following statuses are defined:
- `INIT`	Initialized
- `STFF`	Staffed
- `AUTH`	Authorized
- `RJTD`	Rejected
- `LOTO`	Lockout & tagout in place
- `SFTG`	Safety gatekeeping passed
- `TSPI`	Task-specific hazards instruction carried out
- `DEBR`	Complete debriefing (area & equipment + task-specific) confirmed by workers
- `DOPN`	Opened for the day
- `DCLS`	Closed for the day
- `APFN`	Applied for finalization
- `RLTO`	Lockout & tagout removal
- `FINL`	Finalized
- `CNLD`	Canceled
- `MSTF`	Modification in staff underway.

The final two statuses aren't used currently but have been defined for later implementation of new features, like cancelling a permit or modifying team composition.

