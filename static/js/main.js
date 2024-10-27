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
  

 // Show/hide the "add viewer" popup
 var addViewerButton = document.getElementById("addViewerButton");
 var addViewerPopup = document.getElementById("addViewerPopup");

 if (addViewerButton) {
     addViewerButton.addEventListener("click", function () {
         addViewerPopup.style.display = "flex";
         addViewerPopup.style.zIndex = 100;
         addViewerPopup.style.backgroundColor = "rgba(113, 113, 113, 0.3)";
         addViewerPopup.style.alignItems = "center";
         addViewerPopup.style.justifyContent = "center";
     });
 }

 // Close popup when clicked outside
 addViewerPopup.addEventListener("click", function (e) {
     if (e.target === addViewerPopup) {
         addViewerPopup.style.display = "none";
     }
 });

 // Toggle hidden users in search when the arrow (chevron) is clicked
 var chevronIcon = document.getElementById("chevronIcon");
 var hiddenUsers = document.getElementById("hiddenUsers");
 var isUsersVisible = false; // Track visibility state

 chevronIcon.addEventListener("click", function () {
     console.log("Chevron clicked!"); // Debugging log to check click
     isUsersVisible = !isUsersVisible; // Toggle the state
     if (isUsersVisible) {
         hiddenUsers.style.display = "block";
     } else {
         hiddenUsers.style.display = "none";
     }
 });

 // Получение элементов кнопок
 var myViewersButton = document.getElementById("myViewersButton");
 var allUsersButton = document.getElementById("allUsersButton");
 var hiddenUsersList = document.querySelectorAll('.hidden-user');

 // Событие при клике на "My viewers"
 myViewersButton.addEventListener("click", function () {
     hiddenUsersList.forEach(function(user) {
         user.style.display = "none";
     });
     myViewersButton.classList.add("active");
     myViewersButton.classList.remove("passive");
     allUsersButton.classList.add("passive");
     allUsersButton.classList.remove("active");
 });

 // Событие при клике на "All users"
 allUsersButton.addEventListener("click", function () {
     hiddenUsersList.forEach(function(user) {
         user.style.display = "flex";
     });
     allUsersButton.classList.add("active");
     allUsersButton.classList.remove("passive");
     myViewersButton.classList.add("passive");
     myViewersButton.classList.remove("active");
 });


 // Функция для обновления линий у пользователей
 function updateUserLines() {
     // Убираем у всех пользователей класс "last-visible"
     document.querySelectorAll('.user').forEach(user => {
         user.classList.remove('last-visible');
     });

     // Выбираем последний видимый элемент с классом "user"
     const visibleUsers = Array.from(document.querySelectorAll('.user'))
         .filter(user => user.style.display !== 'none');
     
     if (visibleUsers.length > 0) {
         // Добавляем класс "last-visible" последнему видимому пользователю
         visibleUsers[visibleUsers.length - 1].classList.add('last-visible');
     }
 }

 // Вызываем updateUserLines при загрузке страницы
 updateUserLines();

 // Обновляем линии при клике на кнопки
 myViewersButton.addEventListener("click", function () {
     hiddenUsersList.forEach(function(user) {
         user.style.display = "none";
     });
     updateUserLines();
 });

 allUsersButton.addEventListener("click", function () {
     hiddenUsersList.forEach(function(user) {
         user.style.display = "flex";
     });
     updateUserLines();
 });

 //ГРУУУУУУУУУУУУУУУУУУУУУУУУУУУУУУУУУУУУУУУУУУУУУУУУУУУПППТЫЫЫЫЫЫЫЫЫЫЫЫЫЫЫЫЫЫЫЫЫЫЫЫЫЫЫЫЫЫЫ


 	// Show/hide the "create group" popup
   var createGroupButton = document.getElementById("createGroupButton");
   var createGroupPopup = document.getElementById("createGroupContainer");

   if (createGroupButton) {
     createGroupButton.addEventListener("click", function () {
       createGroupPopup.style.display = "flex";
       createGroupPopup.style.zIndex = 100;
       createGroupPopup.style.backgroundColor = "rgba(113, 113, 113, 0.3)";
       createGroupPopup.style.alignItems = "center";
       createGroupPopup.style.justifyContent = "center";
     });
   }

   // Close popup when clicked outside
   createGroupPopup.addEventListener("click", function (e) {
     if (e.target === createGroupPopup) {
       createGroupPopup.style.display = "none";
     }
   });

   ////////////////////////////////
   // Получаем кнопки
   var myGroupsButton = document.getElementById("myGroupsButton");
   var allGroupsButton = document.getElementById("allGroupsButton");
   var allGroups = document.querySelectorAll('.gaming, .lmao, .we-love-cats, .fortnite, .dota2, .harry-potter');

   // Функция для отображения первых 4 видимых групп
   function showLimitedGroups() {
     allGroups.forEach((group, index) => {
       if (index < 4) {
         group.style.display = "flex";
       } else {
         group.style.display = "none";
       }
     });
   }

   // Функция для отображения всех групп
   function showAllGroups() {
     allGroups.forEach(group => {
       group.style.display = "flex";
     });
   }

   // События для кнопок
   myGroupsButton.addEventListener("click", showLimitedGroups);
   allGroupsButton.addEventListener("click", showAllGroups);

   // Вызываем `showLimitedGroups()` при загрузке страницы
   showLimitedGroups();

   ////////////////////////
   // Обновляем видимость линий у всех видимых групп
   function updateLines() {
     // Получаем все видимые группы
     var visibleGroups = Array.from(allGroups).filter(group => group.style.display === "flex");
     
     // Показываем линии у всех, кроме последней видимой группы
     visibleGroups.forEach((group, index) => {
       var line = group.querySelector('.line');
       if (line) {
         line.style.display = (index === visibleGroups.length - 1) ? "none" : "block";
       }
     });
   }

   // Обновляем кнопки для вызова функции updateLines
   myGroupsButton.addEventListener("click", () => {
     showLimitedGroups();
     updateLines();
   });

   allGroupsButton.addEventListener("click", () => {
     showAllGroups();
     updateLines();
   });

   // Вызываем `updateLines()` при загрузке страницы
   updateLines();

   ////////////////////////
   // Получение элементов кнопок
   var myGroupsButton = document.getElementById("myGroupsButton");
   var allGroupsButton = document.getElementById("allGroupsButton");
   var hiddenUsersList = document.querySelectorAll('.hidden-user');

   // Событие при клике на "My Groups"
   myGroupsButton.addEventListener("click", function () {
     hiddenUsersList.forEach(function(user) {
       user.style.display = "none"; 
     });
     myGroupsButton.classList.add("active");
     myGroupsButton.classList.remove("passive");
     allGroupsButton.classList.add("passive");
     allGroupsButton.classList.remove("active");
   });

   // Событие при клике на "All Groups"
   allGroupsButton.addEventListener("click", function () {
     hiddenUsersList.forEach(function(user) {
       user.style.display = "flex"; 
     });
     allGroupsButton.classList.add("active");
     allGroupsButton.classList.remove("passive");
     myGroupsButton.classList.add("passive");
     myGroupsButton.classList.remove("active");
   });
			///////////////////
			// Получаем иконку и блок опций приватности
			var privacyIcon = document.querySelector(".window-create-group .window-privacy", ".window-create-group .icon");
			var privacyOptions = document.getElementById("privacyOptions");
			var groupPrivacyText = document.querySelector(".default");

			// Функция для переключения видимости окна с опциями приватности
			privacyIcon.addEventListener("click", function() {
				privacyOptions.style.display = (privacyOptions.style.display === "none" || privacyOptions.style.display === "") ? "block" : "none";
			});

			// Обработка клика по опциям приватности
			privacyOptions.addEventListener("click", function(event) {
				if (event.target.classList.contains("privacy-option")) {
					var privacySetting = event.target.getAttribute("data-privacy");
					groupPrivacyText.textContent = privacySetting.charAt(0).toUpperCase() + privacySetting.slice(1);

					// Скрываем опции после выбора
					privacyOptions.style.display = "none";
				}
			});

			// Закрытие окна опций при клике вне области
			document.addEventListener("click", function(event) {
				if (!privacyOptions.contains(event.target) && event.target !== privacyIcon) {
					privacyOptions.style.display = "none";
				}
			});