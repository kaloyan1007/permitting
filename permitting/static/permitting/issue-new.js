document.addEventListener('DOMContentLoaded', function() {
    let targetedEquipmentDd = document.querySelector('#id_targeted_equipment');
    targetedEquipmentDd.addEventListener('change', function() {
        // Get the selected equipment
        let equipmentId = this.selectedOptions[0].value;

        // Query API to get the area related risks and required personal protection,
        // based on the equipment's area property
        fetch(`/risks-and-pps-by-eq?equipment_id=${equipmentId}`)
        .then(response => response.json())
        .then(data => {
            // Pre-select the risks, matching the equipment's area
            data.riskIds.forEach((id) => {
                selectDdOptionsBasedOnId(document.querySelector('#id_risks'), id)
            });

            // Pre-select the personal protection, matching the equipment's area
            data.personalProtectionIds.forEach((id) => {
                selectDdOptionsBasedOnId(document.querySelector('#id_personal_protection'), id)
            });
        });

    });

    function selectDdOptionsBasedOnId(dd, id) {

        Array.from(dd.options).forEach((o) => {
            if (parseInt(o.value) === parseInt(id)) {
                o.selected = true;
            } else {
                o.selected = false;
            }
        });
    }

});
