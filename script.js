const input = document.getElementById("passwordInput");
const fill = document.getElementById("strengthFill");
const text = document.getElementById("strengthText");

input.addEventListener("input", () => {
    const value = input.value;
    let strength = 0;

    if (value.length > 6) strength++;
    if (/[A-Z]/.test(value)) strength++;
    if (/[0-9]/.test(value)) strength++;
    if (/[^A-Za-z0-9]/.test(value)) strength++;

    let width = (strength / 4) * 100;
    fill.style.width = width + "%";

    if (strength === 1) {
        fill.style.background = "red";
        text.textContent = "ضعيفة جداً";
    } 
    else if (strength === 2) {
        fill.style.background = "orange";
        text.textContent = "ضعيفة";
    } 
    else if (strength === 3) {
        fill.style.background = "yellow";
        text.textContent = "متوسطة";
    } 
    else if (strength === 4) {
        fill.style.background = "lime";
        text.textContent = "قوية";
    } 
    else {
        text.textContent = "";
        fill.style.width = "0%";
    }
});
