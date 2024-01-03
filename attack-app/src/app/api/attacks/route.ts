import { NextResponse, type NextRequest } from "next/server";

export async function GET(
  req: NextRequest,
) {
  try{
  console.log("GET REQUEST RUN")
  return NextResponse.json(
    {
      id: document.displayId,
      title: document.title,
      content: document.content,
      messages: dbMessages,
      announcedMsg: announcedMsg,
    },
    { status: 200 },
  );
} catch (error) {
  return NextResponse.json(
    {
      error: "Internal Server Error",
    },
    {
      status: 500,
    },
  );
  }
}