/**
 * 
 * 
 * Some scenarios about testing websockets that could be automated via unit and e2e testing.
 * 
 * 
 * 
 */

/*
* -------------------------------
 * TEST: When I opened the browser on the app main page, then select an apportunity in the list, I shall see the opportunity.
 * 
 * DEFECT: when you click on one, the console log shows that 2 times, the opportunity was loaded from backend as well as history...
*/

/*
* -------------------------------
 * TEST: When I opened the browser on the opportunity detail page after cleaning my browser cache, I should be redirected on the main screen since no opportunity has been selected.
 * 
 * DEFECT: We get a white screen.
*/

/* 
* -------------------------------
* TEST: When I am on detail screen of my selected opportunity, I shall see an history empty
*
* DEFECT: 
* - The history area is not visible if I resize the screen, IMPORTANT!
* - When I scroll, the history panel behaves (hides then shows then hides as I scroll)
*/

/*
* -------------------------------
* TEST: When User is on the detail screen of its selected opportunity with the history panel opened, the screen shall display the panel open even when browser is refreshed
*
* DEFECT: Failed
*/

/*
* -------------------------------
* TEST: When A User modifies the due date, opportunity in the detail screen of its selected opportunity, the information shall be reflected on the dashboard opportunity list of the other users in real time
*
* DEFECT: Failed, you have to click refresh on the screen. 
*/

/*
* -------------------------------
* TEST: When A User creates a new opportunity, the opportunity shall be displayed on the dashboard opportunity list of the other users in real time
*
* DEFECT: Failed, you have to click refresh on the screen. 
*/

/* 
* -------------------------------
* TEST: if the backend returns an error (ex throw an exception to test) while reading load history, the client shall have a strategy to inform user and retry to get the data.
*
* DEFECT: Not Handled (loadHistory). user will not be aware of some changes and overwrite them. (need good thinking there)
*/

/* 
* -------------------------------
* TEST: When I and another person are on the detail screen of the same opportunity and one modify the name, the new name shall be reflected on my 2 browsers, and the first revision shall be created
*
* PASSED 
*
* ENHANCEMENT:
* - the entire history was received by the client who got notified, instead of the missing history record 
* - as well as the entire opportunity, even though it was just a letter added to the description name.
* 
*/

/*
* -------------------------------
* TEST: When I click on a previous revision of the history, the screen shall reflect the revision data, and revision record shall be selected only on the user's machine, not on the screen of another user.
*
* PASSED
*/

/*
* -------------------------------
* TEST: When I click on a previous revision in the history panel, then modify it, the new revision shall be created based on its data plus the modification just made and NOT on the lastest revision in the history.
*
* PASSED
*/

/*
* -------------------------------
* TEST: When I click on a previous revision of the history, but then click on the refresh browser, I shall see the revision I selected
*
* DEFECT: Failed
*/

/*
* -------------------------------
* TEST: When user modifies/gives the name to a revision, then name shall be saved in the db and the other user shall see the update in its history panel
*
* DEFECT: Failed, not showing on the other screen, I had to refresh the page
*/

/*
* -------------------------------
* TEST: When user looks at a revision record in this history panel, something shall let that person know that the revision was created out of another revision.
*
* ENHANCEMENT: Simple idea: the revision row where the change was applied could be highlighted with a different color.
* ENHANCEMENT 2: a hint with what was modified in the revision (ex: Resource modification, opportunity description modification) and who did it!
*/

/*
* -------------------------------
* TEST: When user searches by revision name in the history panel, the history panel shall return a filtered result
*
* DEFECT: Currently not implemented
*/

/*
* -------------------------------
* TEST: When user creates a new opportunity, the screen shall show the new opportunity
*
* PASSED
 
*/

/*
* -------------------------------
* TEST: When user edits a block, move or change size of a bloc, add a new person, change start date of person, the system shall reflect the changes to other users on the same screen.
*
* PASSED 
*
*/

/*
* -------------------------------
* TEST: When user wants to modify the hours of a resource for a specific day, a hour input should appear on the chart.
*
* FAILED: the hours input are shows but disappears right away. 
*
*/

/*
* -------------------------------
* TEST: When user moves a block quickly to multiple different positions, or resize multiple times, the system shall submit the changes when the user makes a final stop.
*
* ENHANCEMENT: 
* - Debounce to decrease network access.
* - it is difficult to know which date the block starts at (we just know it is somewhere between 2 dates)
*/
