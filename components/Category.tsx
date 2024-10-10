import Searchbar from "@/components/Searchbar";

const Category = () =>{
    return(
        <>
            <div className="flex-1 p-6">
                <Searchbar/>
                <div className="grid grid-cols-4 gap-2">
                    <div className="bg-purple-500 text-white p-4 rounded-lg">
                        <h3 className="font-semibold">Sent</h3>
                        <p>480 files</p>
                    </div>
                    <div className="bg-green-500 text-white p-4 rounded-lg">
                        <h3 className="font-semibold">Received</h3>
                        <p>190 files</p>
                    </div>
                    <div className="bg-pink-500 text-white p-4 rounded-lg">
                        <h3 className="font-semibold">Videos</h3>
                        <p>30 files</p>
                    </div>
                    <div className="bg-blue-500 text-white p-4 rounded-lg">
                        <h3 className="font-semibold">Audio</h3>
                        <p>80 files</p>
                    </div>
                </div>
                </div>
        </>
    )
}
export default Category;