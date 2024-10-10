const Sidebar  = () =>{
    return(
        <>
            <div className="w-1/6 bg-blue-800 text-white p-4">
                <div className="flex items-center mb-6">
                    <img src="https://openui.fly.dev/openui/64x64.svg?text=👤" alt="Profile"
                         className="rounded-full w-16 h-16 mr-4"/>
                    <h2 className="text-lg font-semibold">My Profile</h2>
                </div>
                <nav>
                    <ul>
                        <li className="mb-4">
                            <a href="#" className="hover:underline">
                                My Profile
                            </a>
                        </li>
                        <li className="mb-4">
                            <a href="#" className="hover:underline">
                                Shared Files
                            </a>
                        </li>
                        <li className="mb-4">
                            <a href="#" className="hover:underline">
                                Favorites
                            </a>
                        </li>
                        <li className="mb-4">
                            <a href="#" className="hover:underline">
                                Upload Files
                            </a>
                        </li>
                    </ul>
                </nav>
                <div className="mt-auto">

                    <a href="#" className="text-sm hover:underline">
                        Log Out
                    </a>
                </div>
            </div>
        </>
    )
}

export default Sidebar;