
function main(){
	
	// Taking inputs from the user
	let plaintext = "Hi how are you doing";
	let key = "12121212";

	// Determining if padding is required
	let isPaddingRequired = (plaintext.length % 8 != 0);

	//  Encryption
    let ciphertext = DESEncryption(key, plaintext, isPaddingRequired);

    //  Decryption
    let decipheredtext = DESDecryption(key, ciphertext, isPaddingRequired);

	console.log(ciphertext);
	console.log(decipheredtext);

}

// Permutation Matrix used after each SBox substitution for each round
const eachRoundPermutationMatrix = [
    16, 7,  20, 21, 29, 12, 28, 17,
    1,  15, 23, 26, 5,  18, 31, 10,
    2,  8,  24, 14, 32, 27, 3,  9,
    19, 13, 30, 6,  22, 11, 4,  25
]

// Final Permutation Matrix for data after 16 rounds
const finalPermutationMatrix = [
    40, 8, 48, 16, 56, 24, 64, 32,
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41, 9,  49, 17, 57, 25
]

// """Function for DES Encryption."""
function DESEncryption(key, text, padding){

    // Adding padding if required
    if (padding == true)
        text = addPadding(text);
	
    //  Encryption
    let ciphertext = DES(text, key, padding, true);
    
    //  Returning ciphertext
    return ciphertext;
}

// """Function for DES Decryption."""
function DESDecryption(key, text, padding){

	//  Decryption
	let plaintext = DES(text, key, padding, false);
	
    // Remove padding if required
    if (padding == true)
		return removePadding(plaintext);
	
    //  Returning plaintext
    return plaintext;
}

// Initial Permutation Matrix for data
const initialPermutationMatrix = [
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9,  1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7
]

// Expand matrix to get a 48bits matrix of datas to apply the xor with Ki
const expandMatrix = [
    32, 1,  2,  3,  4,  5,
    4,  5,  6,  7,  8,  9,
    8,  9,  10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32, 1
]


// Function to implement DES Algorithm.
function DES(text, key, padding, isEncrypt){

	// Initializing variables required
    let isDecrypt = !isEncrypt;
	
	// Generating keys
    let keys = generateKeys(key)
    
    // Splitting text into 8 byte blocks
    let plaintext8byteBlocks = nSplit(text, 8)
	let result = []

	// For all 8-byte blocks of text
    for(let j = 0; j < plaintext8byteBlocks.length; j++){
		
		let block = plaintext8byteBlocks[j];

		// Convert the block into bit array
        block = stringToBitArray(block)

        // Do the initial permutation
        block = permutation(block, initialPermutationMatrix)

        // Splitting block into two 4 byte (32 bit) sized blocks
		let blocks = nSplit(block, 32);
		let leftBlock = blocks[0];
		let rightBlock = blocks[1];
        
        let temp = "";
        
		// Running 16 identical DES Rounds for each block of text
		for(let i = 0; i < 1; i++){
			// Expand rightBlock to match round key size(48-bit)
            let expandedRightBlock = expand(rightBlock, expandMatrix)
            
            // Xor right block with appropriate key
            if(isEncrypt){
				//  For encryption, starting from first key in normal order
                temp = xor(keys[i], expandedRightBlock)
                
			}
            else if(isDecrypt){
				//  For decryption, starting from last key in reverse order
                temp = xor(keys[15 - i], expandedRightBlock)
			}   
            
            //  Sbox substitution Step
            temp = SboxSubstitution(temp)
            
            
            //  Permutation Step
            temp = permutation(temp, eachRoundPermutationMatrix)
            //  XOR Step with leftBlock
            temp = xor(leftBlock, temp)

            //  Blocks swapping
            leftBlock = rightBlock
            rightBlock = temp
		}
        
		//  Final permutation then appending result
        result = result.concat(permutation(rightBlock.concat(leftBlock), finalPermutationMatrix));
    }
    
	// Converting bit array to string
	let finalResult = bitArrayToString(result)
	
	return finalResult;
}

// Matrix used for shifting after each round of keys
const SHIFT = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

// Permutation matrix for key
const keyPermutationMatrix1 = [
    57, 49, 41, 33, 25, 17, 9,
    1, 58, 50, 42, 34, 26, 18,
    10, 2, 59, 51, 43, 35, 27,
    19, 11, 3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15,
    7, 62, 54, 46, 38, 30, 22,
    14, 6, 61, 53, 45, 37, 29,
    21, 13, 5, 28, 20, 12, 4
]

// Permutation matrix for shifted key to get next key
const keyPermutationMatrix2 = [
    14, 17, 11, 24, 1, 5, 3, 28,
    15, 6, 21, 10, 23, 19, 12, 4,
    26, 8, 16, 7, 27, 20, 13, 2,
    41, 52, 31, 37, 47, 55, 30, 40,
    51, 45, 33, 48, 44, 49, 39, 56,
    34, 53, 46, 42, 50, 36, 29, 32
]

// Function to generate keys for different rounds of DES.
function generateKeys(key){
	
	// Inititalizing variables required
    let keys = []
    key = stringToBitArray(key)
    
    // Initial permutation on key
    key = permutation(key, keyPermutationMatrix1)

    // Split key in to (leftBlock->LEFT), (rightBlock->RIGHT)
	let keyBlocks = nSplit(key, 28);
	
	let leftBlock = keyBlocks[0];
	let rightBlock = keyBlocks[1];
	// 16 rounds of keys
	for(let i = 0; i < 16; i++){
		//  Do left shifting (different for different rounds)
		leftBlock = leftShift(leftBlock, SHIFT[i]);
		rightBlock = leftShift(rightBlock, SHIFT[i]);

        //  Merge them
        temp = leftBlock.concat(rightBlock);
        
        //  Permutation on shifted key to get next key
        keys.push(permutation(temp, keyPermutationMatrix2))

	}
	//  Return generated keys
    return keys
}

//  Sboxes used in the DES Algorithm
const SboxesArray = [
    [
        [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
        [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
        [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
        [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13],
    ],

    [
        [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
        [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
        [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
        [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9],
    ],

    [
        [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
        [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
        [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
        [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12],
    ],

    [
        [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
        [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
        [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
        [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14],
    ],

    [
        [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
        [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
        [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
        [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3],
    ],

    [
        [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
        [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
        [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
        [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13],
    ],

    [
        [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
        [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
        [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
        [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12],
    ],

    [
        [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
        [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
        [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
        [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11],
    ]
]


// Function to substitute all the bytes using Sbox
function SboxSubstitution(bitArray){
	// Split bit array into 6 sized chunks
    // For Sbox indexing
    let blocks = nSplit(bitArray, 6);
	let result = [];
	
	for(let i = 0; i < blocks.length; i++){
        let block = blocks[i];
        let column = '';
		// Row number to be obtained from first and last bit
        let row = parseInt(block[0].toString().concat(block[5].toString()), 2);
        // Getting column number from the 2,3,4,5 position bits
        for(let i=1;i<=4;i++)   column = column.concat(block[i].toString());
        
        column = parseInt(column, 2);  
        
        // Taking value from ith Sbox in ith round
        let sboxValue = SboxesArray[i][row][column]
        
        // Convert the sbox value to binary
        let binVal = binValue(sboxValue, 4)
        
        let bitArr = [];
        for(let i=0;i<binVal.length;i++){
            let bit = binVal[i];
            bit = parseInt(bit);
            bitArr.push(bit);
        }

        // Appending to result
        result = result.concat(bitArr);
    }
    
    // returning result
    return result;
}


// """Function to add padding according to PKCS5 standard."""
function addPadding(text){
    //  Determining padding length
	paddingLength = 8 - (text.length % 8);
	
    //  Adding paddingLength number of charcode(paddingLength) to text
    let chartoAdd = String.fromCharCode(paddingLength);
    
	let s = "";
	for(var i=0;i<paddingLength;i++)	s = s.concat(chartoAdd); 
	
	//  Returning text
	return text = text.concat(s);
}

// Function to remove padding from plaintext according to PKCS5.
function removePadding(data){

	// Getting padding length
	let paddingLength = data.charCodeAt(data.length - 1);

	// Returning data with removed padding
	return data.substring(0,data.length - paddingLength);
}

// Function to expand the array using table
function expand(array, table){
    let ans = [];
    // expanding the original matrix ans store the new in ans
    for(let i = 0; i <table.length; i++){
        ans[i] = array[table[i]-1];
    }
    // # Returning expanded result
    return ans;
}

// Function to do permutation on the array using table
function permutation(array, table){
    let ans = [];
    for(let i = 0; i <table.length; i++){
        ans[i] = array[table[i]-1];
    }
    // # Returning permuted result
    return ans;
}

// Function to left shift the arrays by n
function leftShift(list, n){
    // Left shifting the array
	return list.slice(n).concat(list.slice(0, n));
}

// Function to split a list into chunks of size n
function nSplit(list, n){
    let splittedList = [];
    for(let i = 0; i < list.length; i = i+n){
        splittedList.push(list.slice(i,i+n))
    }
    return splittedList;
}

// Function to return the XOR of two lists
function xor(list1, list2){
    let ans = [];
    for(let i=0;i<list1.length;i++){
        ans[i] = list1[i] ^ list2[i];
    }
    return ans;
}

// Function to return the binary value as a string of given size
function binValue(val, bitSize){
    let binVal = "";
    
    // convert val to binary value
    if(!isNaN(val)){
        
        binVal = parseInt(val, 10).toString(2)
    }
    else{
        
        for (var i = 0; i < val.length; i++) {
            binVal += val[i].charCodeAt(0).toString(2);
        }
    }
    
    
    // making size of binVal equal to bitsize
    while(binVal.length < bitSize)  binVal = "0" + binVal;
    
    // Returning binary value
    return binVal
}

// Funtion to convert a string into a list of bits
function stringToBitArray(text){
    // Initializing variable required
    let bitArray = []
    let idx = 0;
    for(let i=0;i<text.length;i++){
        letter = text[i];
        // Getting binary (8-bit) value of   letter
        binVal = binValue(letter, 8)
        
        // Making list of the bits
        for(var j=0;j<binVal.length;j++){
            bitArray[idx] = parseInt(binVal[j]);
            idx++; 
        }
    }
    //Returning answer
    return bitArray
}

// Function to convert a list of bits to string
function bitArrayToString(array){
    // Chunking array of bits to 8 sized bytes
    let byteChunks = nSplit(array, 8)
    
    // # Initializing variables required
    let stringBytesList = []
    let stringResult = []
    
    // # For each byte in bytechunks
    for(let i = 0; i < byteChunks.length; i++){
        
        let bitsList = []
        let byte = byteChunks[i];
        
        for(let j = 0; j < byte.length; j++){
            bit = byte[j];
            bitsList.push(bit.toString());
        }
        
        // Appending byte in string form to stringBytesList
        stringBytesList.push(bitsList.join(""));
    }

    // Converting each stringByte to char (base 2 int conversion first)
    // and then concatenating
    for(let i=0;i<stringBytesList.length;i++){
        let stringByte = stringBytesList[i];
        let numInBase2 = parseInt(stringByte, 2);
        stringResult.push(String.fromCharCode(numInBase2));
    }

    let result = stringResult.join('');

    // # Returning result
    return result
}

main();
