function updateFileName() {
    var fileInput = document.getElementById("file-upload");
    var label = document.getElementById("file-label");
    if (fileInput.files.length > 0) {
        label.setAttribute("data-content", fileInput.files[0].name);
        label.classList.add("file-selected");
    } else {
        label.setAttribute("data-content", "No file chosen");
        label.classList.remove("file-selected");
    }
}

function showProgressBar() {
    var progressBar = document.getElementsById("progress-container");
    progressBar.style.display = "block";
}


const uploadForm = document.getElementById("upload-form");
const fileUploadInput = document.getElementById("file-upload");
const progressBar = document.getElementById("progress-bar");
const progressText = document.getElementById("progress-text");

uploadForm.addEventListener("submit", function (event) {
    event.preventDefault();

    const xhr = new XMLHttpRequest();
    xhr.open("POST", "/upload");

    xhr.upload.onprogress = function (event) {
        if (event.lengthComputable) {
            const progress = Math.round((event.loaded / event.total) * 100);
            progressBar.style.width = progress + "%";
            progressText.textContent = progress + "%";
        }
    };

    xhr.onload = function () {
        // File upload completed
        progressBar.style.width = "100%";
        progressText.textContent = "Upload completed";
        console.log("Upload completed");
        setTimeout(function () {
            progressBar.style.width = "0%";
            progressText.textContent = "0%";
        }, 2000);
    };

    xhr.onerror = function () {
        // Error occurred during file upload
        progressBar.style.width = "0%"; 
        progressText.textContent = "Upload failed";
        console.log("Upload failed");
    };

    const formData = new FormData(uploadForm);
    xhr.send(formData);
});







