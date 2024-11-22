 // Show the flash message container and fade out the messages after a few seconds
 window.onload = function() {
  const flashMessages = document.querySelectorAll('.flash-message');
  if (flashMessages.length > 0) {
      const flashContainer = document.getElementById('flashMessages');
      flashContainer.style.display = 'flex';  // Show flash messages

      setTimeout(() => {
          flashMessages.forEach(message => {
              message.style.opacity = '0';  // Fade out the message
          });

          // Optionally, hide the container after all messages fade out
          setTimeout(() => {
              flashContainer.style.display = 'none';
          }, 1000);
      }, 3000);  // Keep the messages visible for 3 seconds
  }
};
//sidebar func
function toggleNav() {
    const sidebar = document.getElementById("mySidebar");
    //const container = document.querySelector('.projekt-container'); // Select the container
    if (sidebar.style.width === "400px") {
      sidebar.style.width = "0"; // Close the sidebar
      //container.style.marginRight = "0"; // Reset container margin
      sidebar.style.visibility = "hidden";
    } else {
      sidebar.style.width = "400px"; // Open the sidebar
      //container.style.marginRight = "400px"; // Adjust the container to fit the sidebar
      sidebar.style.visibility = "visible";
    }
  }


//menu scroll reaction
  window.onscroll = function () {
    adjustHeaderOnScroll();
  };
  
  function adjustHeaderOnScroll() {
    const header = document.querySelector('.projekt-header');
    const searchBar = document.querySelector('.projekt-search1');
    const scrollTop = document.documentElement.scrollTop;
  
    if (scrollTop > 50) {
      // Set top to 0 to keep it fixed but appear as if it's moved
      header.style.marginTop = '0';
      searchBar.style.top = '7px';
      header.style.backgroundColor = 'rgba(205, 226, 250, 0.8)'; // Add transparency
    } else {
      // Reset top to initial value when at the top
      header.style.marginTop = '20px';
      searchBar.style.top = '27px';
      header.style.backgroundColor = 'rgba(205, 226, 250, 1)';
    }
  }
  function togglePassword() {
    var passwordField = document.getElementById("password");
    var passwordIcon = document.getElementById("togglePasswordIcon");
    
    if (passwordField.type === "password") {
        passwordField.type = "text";
        passwordIcon.classList.remove("fa-eye-slash");
        passwordIcon.classList.add("fa-eye");
    } else {
        passwordField.type = "password";
        passwordIcon.classList.remove("fa-eye");
        passwordIcon.classList.add("fa-eye-slash");
    }
}

function toggleConfirmPassword() {
    var confirmPasswordField = document.getElementById("confirm_password");
    var confirmPasswordIcon = document.getElementById("toggleConfirmPasswordIcon");
    
    if (confirmPasswordField.type === "password") {
        confirmPasswordField.type = "text";
        confirmPasswordIcon.classList.remove("fa-eye-slash");
        confirmPasswordIcon.classList.add("fa-eye");
    } else {
        confirmPasswordField.type = "password";
        confirmPasswordIcon.classList.remove("fa-eye");
        confirmPasswordIcon.classList.add("fa-eye-slash");
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

function toggleSharePopup() {
  const sharePopup = document.getElementById("sharePopupModal");
  sharePopup.style.display = (sharePopup.style.display === "none" || sharePopup.style.display === "") ? "block" : "none";
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

      function likeComment(commentId) {
        fetch(`/like_comment/${commentId}`, {
            method: 'POST',
        })
        .then(response => response.json())
        .then(data => {
            // Обновляем количество лайков на странице
            const likesCount = document.querySelector(`#comment-${commentId} .likesCount`);
            likesCount.textContent = `Likes: ${data.likes}`;
        })
        .catch(error => console.error('Error:', error));
    }
    function toggleSearchBar() {
      var searchForm = document.getElementById('searchBarContainer');
      if (window.innerWidth < 1200) {
        searchForm.classList.toggle('hidden');
      }
    }
  