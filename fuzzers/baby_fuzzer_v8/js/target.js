export default function(data) {
    let array = new Uint8Array(data);
    if (array.length > 1 && array[0] === 'A'.charCodeAt(0)) {
        console.log("howdy")
        if (array.length > 2 && array[1] === 'B'.charCodeAt(0)) {
            console.log("kachowdy")
            if (array.length > 2 && array[2] === 'C'.charCodeAt(0)) {
                throw "crash!";
            }
        }
    }
}
