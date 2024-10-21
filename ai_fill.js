// // Path to the folder containing images



function placeQRCodeOnArtboard(doc, artboardIndex, filePath, x, y) {
    // Ensure the artboard index is within the valid range
    if (artboardIndex < 0 || artboardIndex >= doc.artboards.length) {
        $.writeln("Invalid artboard index.");
        return;
    }

    // Set the active artboard to the one specified by artboardIndex
    doc.artboards.setActiveArtboardIndex(artboardIndex);
    var artboard = doc.artboards[artboardIndex];

    // Calculate position relative to the artboard
    var abBounds = artboard.artboardRect; // [left, top, right, bottom]
    var posX = abBounds[0] + x; // left + x
    var posY = abBounds[1] - y; // top - y

    // Place the QR code image
    var placedItem = doc.placedItems.add();
    placedItem.file = new File(filePath);
    placedItem.position = [posX, posY]; // Set the position relative to the artboard

    // Optionally, resize the QR code
    var desiredWidth = 100; // Desired width in points
    var scaleFactor = desiredWidth / placedItem.width; // Calculate scale factor
    placedItem.width = desiredWidth;
    placedItem.height *= scaleFactor; // Scale height to maintain aspect ratio

    //  // Export the document as a PDF
    //  var pdfFile = new File('pdfs/test_pdf.pdf');
    //  var pdfOptions = new PDFSaveOptions();
    //  pdfOptions.preset = '[High Quality Print]';
    //  doc.saveAs(pdfFile, pdfOptions);
    //  app.activeDocument.close(SaveOptions.DONOTSAVECHANGES); // Close the document without saving changes

    return placedItem;
}

function exportAsPDF(doc, outputFilePath) {
    var pdfOptions = new PDFSaveOptions();
    pdfOptions.preset = '[High Quality Print]';
    pdfOptions.viewAfterSaving = false;
    pdfOptions.optimizeForFastWebView = false; // Set to false unless needed
    pdfOptions.acrobatLayers = false;
    pdfOptions.interactiveElements = false;

    // Convert to an absolute path
    var outputFile = new File(outputFilePath);
    if (!outputFile.parent.exists) {
        outputFile.parent.create();  // Attempt to create the directory if it does not exist
    }

    try {
        doc.saveAs(outputFile, pdfOptions);
        $.writeln("PDF saved successfully to: " + outputFile.fsName);
    } catch (e) {
        $.writeln("Error saving PDF: " + e.message);
    }
}


function getFileNameWithoutExtension(path) {
    // Extract the last part of the path (the file name with extension)
    var fileNameWithExtension = path.split('/').pop(); // This works if the path separator is '/'

    // Remove the extension from the file name
    var fileName = fileNameWithExtension.split('.').slice(0, -1).join('.');

    // Handle cases where the file has no extension but the dot is part of the file name
    if (fileName === "") {
        fileName = fileNameWithExtension; // There was no extension
    }

    return fileName;
}



var doc = app.activeDocument; // Assumes a document is already open
var imagesFolder = Folder.selectDialog();
var files = imagesFolder.getFiles(/\.(jpg|jpeg|png|gif)$/i); // Filter for image files

var previousPlacedItem = null; // Track the previously placed item
// Loop through all files and place them
for (var i = 0; i < files.length; i++) {
    if (previousPlacedItem != null) {
        previousPlacedItem.remove();
    }
    var uName = files[i];
    // var newName = getFileNameWithoutExtension(uName);
    // var base = 'pdfs/';
    var base = '/Users/stevennichols/Desktop/donuts/giftcards/pdfs/';
    var final_file_name = base.concat(i, '.pdf');
    // alert(final_file_name);
    previousPlacedItem = placeQRCodeOnArtboard(doc, 0, files[i], 124, 26);
    // var fname = '/Users/stevennichols/Desktop/donuts/giftcards/pdfs/'+uName+ '.pdf';
    exportAsPDF(doc, final_file_name);

}


