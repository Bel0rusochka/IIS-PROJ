//sidebar func
function toggleNav() {
    const sidebar = document.getElementById("mySidebar");
    const container = document.querySelector('.projekt-container'); // Select the container
    if (sidebar.style.width === "400px") {
      sidebar.style.width = "0"; // Close the sidebar
      container.style.marginRight = "0"; // Reset container margin
      sidebar.style.visibility = "hidden";
    } else {
      sidebar.style.width = "400px"; // Open the sidebar
      container.style.marginRight = "400px"; // Adjust the container to fit the sidebar
      sidebar.style.visibility = "visible";
    }
  }


//menu scroll reaction
  window.onscroll = function () {
    adjustHeaderOnScroll();
  };
  
  function adjustHeaderOnScroll() {
    const header = document.querySelector('.projekt-header');
    const scrollTop = window.pageYOffset || document.documentElement.scrollTop;
  
    if (scrollTop > 50) {
      // Set margin-top to 0 and make the background transparent when scrolling
      header.style.marginTop = '0';
      header.style.backgroundColor = 'rgba(205, 226, 250, 0.8)'; // Add transparency
    } else {
      // Reset margin-top and background when at the top
      header.style.marginTop = '20px';
      header.style.backgroundColor = 'rgba(205, 226, 250, 1)';
    }
  }

  
// Toggle the popup modal
function togglePopup() {
    var popup = document.getElementById('popupModal');
    var imageInput = document.getElementById('imageUpload');
    var captionInput = document.getElementById('caption');
    var tagsInput = document.getElementById('tags');
    var dropZone = document.getElementById('dropZone');

    if (popup.style.display === 'none' || popup.style.display === '') {
        popup.style.display = 'block';
    } else {
        // Reset inputs and clear image preview
        imageInput.value = ''; // Clear the file input
        captionInput.value = ''; // Clear the caption
        tagsInput.value = ''; // Clear the tags
        dropZone.style.backgroundImage = 'none'; // Clear background image
        dropZone.classList.remove('expanded'); // Remove expanded class if any
        popup.style.display = 'none'; // Close the modal
    }
}

  
  // Placeholder function for the Post button (you can customize this as needed)
  function submitPost() {
    var imageInput = document.getElementById('imageUpload');
    var caption = document.getElementById('caption').value;
    var tags = document.getElementById('tags').value;
  
    if (imageInput.files.length === 0) {
      alert("Please select an image.");
      return;
    }
  
    // This is where you can handle the form data, e.g., sending it to a server
    alert("Post submitted with caption: " + caption + " and tags: " + tags);
  
    // Close the popup after submission
    togglePopup();
  }
  // Close the popup when clicking outside the popup content
window.onclick = function(event) {
    var popup = document.getElementById('popupModal');
    var content = document.querySelector('.popup-content');
    if (event.target == popup && !content.contains(event.target)) {
        togglePopup();
    }
}
const dropZone = document.getElementById('dropZone');
const imageInput = document.getElementById('imageUpload');

// Event listeners for the drop zone
dropZone.addEventListener('dragover', (e) => {
  e.preventDefault(); // Prevent default behavior to allow drop
  dropZone.classList.add('dragover'); // Add class for visual feedback
});

dropZone.addEventListener('dragleave', () => {
  dropZone.classList.remove('dragover'); // Remove class when not dragging
});

dropZone.addEventListener('drop', (e) => {
  e.preventDefault(); // Prevent default behavior (open as link)
  dropZone.classList.remove('dragover'); // Remove class on drop
  const files = e.dataTransfer.files; // Get dropped files
  if (files.length > 0) {
    displayImage(files[0]); // Display the first file
  }
});

// Allow clicking the drop zone to open file dialog
imageInput.addEventListener('change', (e) => {
  if (e.target.files.length > 0) {
    displayImage(e.target.files[0]); // Display the selected file
  }
});

// Function to display the uploaded image as the background of the drop zone
function displayImage(file) {
    const reader = new FileReader();
    reader.onload = function(e) {
      dropZone.style.backgroundImage = `url(${e.target.result})`; // Set the background image
      dropZone.style.backgroundSize = 'contain'; // Adjust to 'contain' to fit within the drop zone
      dropZone.style.backgroundPosition = 'center'; // Center the background image
      dropZone.style.backgroundRepeat = 'no-repeat'; // Prevent background repeat
      dropZone.style.color = 'transparent'; // Make the text transparent (optional)
    };
    reader.readAsDataURL(file); // Read the file as a data URL
  }
  
