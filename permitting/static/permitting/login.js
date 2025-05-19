document.addEventListener('DOMContentLoaded', function() {
    window.addEventListener('resize', changeLoginFormWidth);
});

function changeLoginFormWidth() {
    document.querySelectorAll('.login-form-elem').forEach(elem => {
        elem.classList.remove('w-25', 'w-50', 'w-75');

        if (window.innerWidth < 500) {
            elem.classList.add('w-75');
        } else if (window.innerWidth > 500 && window.innerWidth < 800) {
            elem.classList.add('w-50');
        } else {
            elem.classList.add('w-25');
        }
    })
    }
