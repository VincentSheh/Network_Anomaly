export default function NavBar(){
  return (
    <div className="bg-white bg-opacity-75 shadow-md border-b border-gray-200 absolute top-0 z-50 w-full flex justify-between">
      <div className="flex flex-col justify-center p-5 relative">
        <h2 className="text-2xl font-bold text-blue-950 md:text-3xl lg:text-4xl xl:text-5xl">
          Simulate an Attack
        </h2>
        <h6 className="text-sm text-gray-600">
          By Vincent Sheh
        </h6>
      </div>
      <span className="flex items-center py-2 px-5 text-lg hover:bg-blue-100 cursor-pointer">
        For Research Purpose Only!
      </span>
    </div>
  );
}
