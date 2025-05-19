import { enableInfoNotifDeactivation, addPaginationListItem, renderNotifsPage } from './helpers.js';

document.addEventListener('DOMContentLoaded', function() {
    loadNotifications();

    document.querySelectorAll('.btn-check').forEach(elem => {
        elem.addEventListener('click', () => {
            loadNotifications()
        });
    })

});

function loadNotifications(page_num=1) {

    const allNotificationsContainer = document.querySelector('#paginated-content');

    // Clear the view of previous content
    allNotificationsContainer.value = '';

    while (allNotificationsContainer.firstChild) {
    allNotificationsContainer.removeChild(allNotificationsContainer.firstChild);
    }

    // Determine toggled notification type
    const actionsBtn = document.querySelector('#btnradio1');
    const infoBtn = document.querySelector('#btnradio2');

    let notifType;

    if (actionsBtn.checked) {
        notifType = "action";
    } else if (infoBtn.checked) {
        notifType = "info";
    }

    // Make API call to fetch the posts
    fetch(`/get-notifications-by-type-page?page=${page_num}&type=${notifType}`)
    .then(response => response.json())
    .then(notifsPage => {
        // Display first page of 3 notifs (page size specified in the endpoint)
        renderNotifsPage(notifsPage, allNotificationsContainer, notifType);

        // Add navigation to next/prev pages
        let paginationNav = document.createElement('nav');
        allNotificationsContainer.append(paginationNav);
        paginationNav.classList.add('m-3', 'mx-auto', 'w-50');

        let paginationUl = document.createElement('ul');
        paginationNav.append(paginationUl);
        paginationUl.classList.add('pagination');

        if (notifsPage.has_previous) {
            addPaginationListItem(
            "Previous",
            () => { loadNotifications(notifsPage.current_page_num - 1); },
            paginationUl
            );
        }

        if (notifsPage.has_next) {
            addPaginationListItem(
            "Next",
            () => { loadNotifications(notifsPage.current_page_num + 1); },
            paginationUl
            );
        }

        // After everything has been loaded, enable deactivation of notifications
        enableInfoNotifDeactivation();

    });

}
