import Image from "next/image";
import Sidebar from "@/components/Sidebar";
import UploadFile from "@/components/UploadFile";
import Category from "@/components/Category";
import Searchbar from "@/components/Searchbar";
export default function Home() {
  return (
    <div className="flex h-screen bg-background">
        <Sidebar/>
      <Category/>
        <UploadFile/>
    </div>
  );
}
