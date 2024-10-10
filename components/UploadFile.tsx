const UploadFile = () =>{
    return(
        <>
            <div className="mt-6 w-1/4">
                <h3 className="font-semibold mb-2">Add new files</h3>
                <div className="mb-4">
                    <input type="text" placeholder="Enter the user ID"
                           className="border border-zinc-300 rounded-lg p-2 w-full"/>
                </div>
                <div className="mb-4">
                    <textarea placeholder="write your notes here"
                              className="border border-zinc-300 rounded-lg p-2 w-full" rows="4"></textarea>
                </div>
                <button className="bg-blue-600 text-white p-2 rounded-lg">Send Document</button>
            </div>
        </>
    )
}
export default UploadFile