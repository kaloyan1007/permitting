import { addPaginationListItem, renderPermitsPage } from './helpers.js';

document.addEventListener('DOMContentLoaded', function() {
    loadPermits();

    document.querySelectorAll('.btn-check').forEach(elem => {
        elem.addEventListener('click', () => {
            loadPermits()
        });
    })

});

function loadPermits(page_num=1) {

    const allPermitsContainer = document.querySelector('#paginated-content');

    // Clear the view of previous content
    allPermitsContainer.value = '';

    while (allPermitsContainer.firstChild) {
    allPermitsContainer.removeChild(allPermitsContainer.firstChild);
    }

    // Determine active or inactive permits to select
    const activePermitsBtn = document.querySelector('#btnradio1');
    const inactivePermitsBtn = document.querySelector('#btnradio2');

    let getActive;

    if (activePermitsBtn.checked) {
        getActive = true;
    } else if (inactivePermitsBtn.checked) {
        getActive = false;
    }

    // Make API call to fetch the permits
    fetch(`/get-permits-page?page=${page_num}&get_active=${getActive}`)
    .then(response => response.json())
    .then(permitsPage => {
        // Display first page of 3 permits (page size specified in the endpoint)
        renderPermitsPage(permitsPage, allPermitsContainer, getActive);

        // Add navigation to next/prev pages
        let paginationNav = document.createElement('nav');
        allPermitsContainer.append(paginationNav);
        paginationNav.classList.add('m-3', 'mx-auto', 'w-50');

        let paginationUl = document.createElement('ul');
        paginationNav.append(paginationUl);
        paginationUl.classList.add('pagination');

        if (permitsPage.has_previous) {
            addPaginationListItem(
            "Previous",
            () => { loadPermits(permitsPage.current_page_num - 1); },
            paginationUl
            );
        }

        if (permitsPage.has_next) {
            addPaginationListItem(
            "Next",
            () => { loadPermits(permitsPage.current_page_num + 1); },
            paginationUl
            );
        }

    });

}
