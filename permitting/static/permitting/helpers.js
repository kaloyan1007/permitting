export function enableInfoNotifDeactivation() {
    const deactivateNotifBtns = document.querySelectorAll('.deactivate-notif-btn');

    deactivateNotifBtns.forEach(btn => {
        btn.addEventListener('click', deactivateNotif);
    })
}

function deactivateNotif() {
    const containerDiv = this.parentElement;

    // Make API call to record notification in DB as deactivated
    fetch('/deactivate-info-notification', {
        method: 'POST',
        body: JSON.stringify({
        id: containerDiv.id
        })
    })
    .then(response => response.json())
    .then(result => {
        // Create a blank div to display a status message
        let msgDiv;

        if (document.querySelector('#msg-div')) {
            msgDiv = document.querySelector('#msg-div');
            msgDiv.className = '';
        }
        else {
            msgDiv = document.createElement('div');
            msgDiv.id = 'msg-div';
            containerDiv.parentElement.append(msgDiv);
        }

        msgDiv.style.display = 'block';
        msgDiv.scrollIntoView({ behavior: 'smooth' });

        // Populate message div according to result & re-load other page content
        if (result.error) {
            msgDiv.innerHTML = result.error;
            msgDiv.classList.add('severe-warning', 'm-3', 'p-3');
        }
        else {
            // Hide notif from view
            containerDiv.style.display = 'none';

            // Update notification counter in main navbar
            let activeNotifCounterContainer = document.querySelector('.info-notif-counter');
            activeNotifCounterContainer.innerHTML = parseInt(activeNotifCounterContainer.innerHTML) - 1;

            // Check if any other info notifications are visible, if not - hide section
            const allInfoNotifsContainers = document.querySelectorAll('.info-notif-container');
            let countOfHiddenNotifs = 0;
            allInfoNotifsContainers.forEach(elem => {
                if (elem.style.display === 'none') {
                    countOfHiddenNotifs++;
                }
            })

            if (allInfoNotifsContainers.length === countOfHiddenNotifs) {
                containerDiv.parentElement.style.display = 'none';
            }
        }
    });
}

export function addPaginationListItem(caption, onClickAction, paginationList) {
    let listItem = document.createElement('li');
    paginationList.append(listItem);
    listItem.classList.add('mx-auto', 'page-item');

    let anchor = document.createElement('a');
    listItem.append(anchor);
    anchor.classList.add('page-link');
    anchor.href = '#';
    anchor.innerHTML = caption;

    listItem.addEventListener('click', onClickAction);

  }

  export function renderNotifsPage(notifsPage, container, notifType) {
    // Display error if any
    if (notifsPage.error) {
        container.innerHTML = notifsPage.error;
    }
    // If no notifications yet
    else if (notifsPage.notifs.length === 0) {
        let statusMsgContainer = document.createElement('div');
        statusMsgContainer.innerHTML = '*** Nothing yet ***';
        container.append(statusMsgContainer);
    }
    // Display notifications
    else {
        notifsPage.notifs.forEach((notif) => {
            let singleNotifContainer = document.createElement('div');
            if (notifType === "info") {
                singleNotifContainer.id = notif.id;
                singleNotifContainer.classList.add('info-notif-container');
            }
            container.append(singleNotifContainer);
            singleNotifContainer.classList.add('border', 'mb-3', 'mx-auto', 'p-3', 'rounded', 'w-50');


            renderSingleNotif(notif, singleNotifContainer, notifType);
        })
    }
}

function renderSingleNotif(notif, singleNotifContainer, notifType) {
    // Create HTML structure
    if (notifType === "info") {
        let deactivateNotifControl = document.createElement('button');
        deactivateNotifControl.type = 'button';
        deactivateNotifControl.ariaLabel = 'Close';
        singleNotifContainer.append(deactivateNotifControl);

        deactivateNotifControl.classList.add('btn-close', 'deactivate-notif-btn', 'float-end');
    }

    let timestampContainer = document.createElement('div');
    const created_on = new Date(notif.created_on);
    const options = {
        month: 'long',
        day: 'numeric',
        year: 'numeric',
        hour: 'numeric',
        minute: 'numeric',
        hour12: true
      };

    timestampContainer.innerHTML = created_on.toLocaleString('de', options);
    singleNotifContainer.append(timestampContainer);
    timestampContainer.classList.add('mb-3', 'muted-elements');

    let notifMessageContainer = document.createElement('div');
    notifMessageContainer.innerHTML = notif.message;
    singleNotifContainer.append(notifMessageContainer);
    notifMessageContainer.classList.add('mb-3');

    let notifLinkContainer = document.createElement('div');
    singleNotifContainer.append(notifLinkContainer);

    if (notifType === "action") {
        let notifLink = document.createElement('a');
        notifLink.href = `/redirect-to-actionview?target_viewname=${notif.target_viewname}&permit_id=${notif.permit_id}`;
        notifLink.innerHTML = 'Details';
        notifLinkContainer.append(notifLink);

        notifLink.classList.add('link-btn');
    }

}

export function renderPermitsPage(permitsPage, container, getActive) {
    // Display error if any
    if (permitsPage.error) {
        container.innerHTML = permitsPage.error;
    }
    // If no associated permits in this stage yet
    else if (permitsPage.permits.length === 0) {
        let statusMsgContainer = document.createElement('div');
        statusMsgContainer.innerHTML = '*** Nothing yet ***';
        container.append(statusMsgContainer);
    }
    // Display permits
    else {
        // Create table
        let permitsTable = document.createElement('table');
        container.append(permitsTable);
        permitsTable.classList.add('table', 'table-responsive', 'table-hover');

        let tHead = document.createElement('thead');
        permitsTable.append(tHead);

        let headingsRow = document.createElement('tr');
        tHead.append(headingsRow);

        // Add headers
        let headings = ['#', 'Task Description', 'Status', 'Area'];
        if (!getActive) {
            headings.push("Finalized On");
        }

        headings.forEach((h) => {
            let th = document.createElement('th');
            th.innerHTML = h;
            headingsRow.append(th);
            th.classList.add('table-primary');
        })

        // Add rows
        let tBody = document.createElement('tbody');
        permitsTable.append(tBody);

        const options = {
            month: 'numeric',
            day: 'numeric',
            year: 'numeric',
          };

        permitsPage.permits.forEach((permit) => {
            let tRow = document.createElement('tr');
            tBody.append(tRow);

            let tD1 = document.createElement('td');

            let toDetailsLink = document.createElement('a');
            toDetailsLink.href = `/permit/${permit.id}`;
            let created_on = new Date(permit.created_on);
            toDetailsLink.innerHTML = permit.id + `/${created_on.toLocaleString('de', options)}`;

            tD1.append(toDetailsLink);
            toDetailsLink.classList.add('minor-link');

            tRow.append(tD1);

            let tD2 = document.createElement('td');
            tD2.innerHTML = permit.task_description;
            tRow.append(tD2);

            let tD3 = document.createElement('td');
            tD3.innerHTML = permit.status;
            tRow.append(tD3);

            let tD4 = document.createElement('td');
            tD4.innerHTML = permit.area;
            tRow.append(tD4);

            if (!getActive) {
                let tD5 = document.createElement('td');
                let finalized_on = new Date(permit.latest_change_on);
                tD5.innerHTML = finalized_on.toLocaleString('de', options);
                tRow.append(tD5);
            }
        })
    }
}
