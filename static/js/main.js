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
  
//-------------------------------IMAGES-----------------------------------------
// const images = document.querySelectorAll('.gallery-image');
// const imageDetail = document.getElementById('imageDetail');
// const selectedImage = document.getElementById('selectedImage');
// const likesCount = document.getElementById('likesCount');
// const retweetsCount = document.getElementById('retweetsCount');
// const commentsCount = document.getElementById('commentsCount');
// const backButton = document.getElementById('backButton');
//
// images.forEach(image => {
//     image.addEventListener('click', function() {
//         const imageId = this.dataset.id;
//
//         // Hide all images in the gallery
//         images.forEach(img => img.style.display = 'none');
//
//         // Show selected image and fetch details
//         selectedImage.src = this.src; // Set the selected image
//         fetchImageDetails(imageId); // Fetch and display details
//         imageDetail.style.display = 'block'; // Show detail area
//     });
// });
// // Assuming you modify the imageDetails object to include tags and comments
// const imageDetails = {
//   1: { likes: 10, retweets: 5, comments: 2, tags: ['nature', 'sunset'], stockComments: ['Beautiful!', 'Amazing shot!'] },
//   2: { likes: 20, retweets: 10, comments: 3, tags: ['city', 'night'], stockComments: ['Love the city lights!', 'Great capture!'] },
//   3: { likes: 30, retweets: 15, comments: 5, tags: ['forest', 'adventure'], stockComments: ['So serene!', 'Incredible view!'] },
//   4: { likes: 40, retweets: 20, comments: 7, tags: ['beach', 'vacation'], stockComments: ['Wish I was there!', 'Looks relaxing!'] },
//   5: { likes: 50, retweets: 25, comments: 10, tags: ['mountain', 'hiking'], stockComments: ['Breathtaking!', 'Nature at its best!'] },
//   6: { likes: 60, retweets: 30, comments: 12, tags: ['ocean', 'waves'], stockComments: ['So calming!', 'I can hear the waves!'] },
//   7: { likes: 70, retweets: 35, comments: 15, tags: ['wildlife', 'animals'], stockComments: ['Cute animal!', 'Wildlife is amazing!'] },
// };
//
// function fetchImageDetails(imageId) {
//   const details = imageDetails[imageId];
//   if (details) {
//       likesCount.innerHTML = `<i class="fa fa-heart"></i> ${details.likes}`;
//       retweetsCount.innerHTML = `<i class="fa fa-retweet"></i> ${details.retweets}`;
//       commentsCount.innerHTML = `<i class="fa fa-comment"></i> ${details.comments}`;
//
//       // Display tags
//       tagsList.innerHTML = details.tags.join(', '); // Join tags with a comma
//
//       // Display stock comments
//       displayStockComments(details.stockComments);
//   }
// }
//
// // Function to display stock comments
// function displayStockComments(stockComments) {
//   const commentsList = document.getElementById('commentsList');
//   commentsList.innerHTML = ''; // Clear existing comments
//   stockComments.forEach(comment => {
//       const commentElement = document.createElement('div');
//       commentElement.textContent = comment; // Add comment text
//       commentsList.appendChild(commentElement); // Append to the comments list
//   });
// }
//
// // Function to handle comment submission
// document.getElementById('submitComment').addEventListener('click', function() {
//   const nicknameInput = document.getElementById('nicknameInput'); // Get nickname input
//   const commentInput = document.getElementById('commentInput'); // Get comment input
//   const nickname = nicknameInput.value.trim(); // Get trimmed nickname
//   const newComment = commentInput.value.trim(); // Get trimmed comment
//
//   if (newComment && nickname) { // Check if both fields are filled
//       const commentsList = document.getElementById('commentsList');
//       const commentElement = document.createElement('div');
//       commentElement.textContent = `${nickname}: ${newComment}`; // Format comment with nickname
//       commentsList.appendChild(commentElement); // Append to comments list
//       commentInput.value = ''; // Clear the comment input
//       nicknameInput.value = ''; // Clear the nickname input
//   } else {
//       alert('Please enter both your nickname and comment.'); // Alert if inputs are empty
//   }
// });
//
// // Handle back button to return to the gallery
// backButton.addEventListener('click', function() {
//   // Show all images again
//   images.forEach(img => img.style.display = 'block');
//   imageDetail.style.display = 'none'; // Hide detail area
// });
